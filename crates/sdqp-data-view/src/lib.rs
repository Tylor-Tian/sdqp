use std::{any::Any, collections::HashMap, io::Cursor, sync::Arc};

use arrow::{
    array::{
        Array, ArrayRef, Float64Array, Int32Array, Int64Array, LargeStringArray, StringArray,
        UInt32Array, UInt64Array,
    },
    datatypes::{DataType, Field, Schema, SchemaRef},
    error::ArrowError,
    ipc::writer::StreamWriter,
    record_batch::RecordBatch,
};
use async_trait::async_trait;
use bytes::Bytes;
use datafusion::{
    catalog::Session,
    dataframe::DataFrame,
    datasource::{TableProvider, TableType},
    error::{DataFusionError, Result as DataFusionResult},
    functions_aggregate::expr_fn::{
        avg, count, count_distinct, max, median, min, percentile_cont, sum,
    },
    logical_expr::{Expr, SortExpr, expr::Sort, expr_fn::cast},
    physical_plan::ExecutionPlan,
    prelude::{SessionContext, col, lit},
};
use datafusion_datasource::{memory::MemorySourceConfig, source::DataSourceExec};
use parquet::{
    arrow::{ArrowWriter, arrow_reader::ParquetRecordBatchReaderBuilder},
    errors::ParquetError,
};
use sdqp_data_classification::{MaskingStrategy, mask_value, recommend_field_classification};
use sdqp_datasource_adapter::FieldQueryResult;
use sdqp_encryption::{
    EncryptedSnapshotRecord, EncryptionError, EnvelopeCipher, SnapshotPayloadFormat,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DataViewError {
    #[error("failed to decrypt snapshot payload")]
    Decryption(#[from] EncryptionError),
    #[error("failed to decode snapshot payload")]
    Decode,
    #[error("no authorized columns are available in snapshot")]
    NoAuthorizedColumns,
    #[error("page size must be greater than zero")]
    InvalidPageSize,
    #[error("requested column `{0}` was not found in snapshot schema")]
    MissingColumn(String),
    #[error("requested column `{0}` is not authorized for this view")]
    UnauthorizedColumn(String),
    #[error("pivot metric field `{0}` contained non-numeric values after masking")]
    NonNumericMetricField(String),
    #[error("pivot percentile must be a finite value between 0.0 and 1.0")]
    InvalidPercentile,
    #[error("arrow processing failed")]
    Arrow(#[from] ArrowError),
    #[error("parquet processing failed")]
    Parquet(#[from] ParquetError),
    #[error("datafusion execution failed")]
    DataFusion(#[from] DataFusionError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedSnapshotPayload {
    pub payload: Vec<u8>,
    pub columns: Vec<String>,
    pub format: SnapshotPayloadFormat,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotPage {
    pub rows: Vec<HashMap<String, String>>,
    pub next_cursor: Option<usize>,
}

#[derive(Debug, Clone)]
pub struct SnapshotBatchPage {
    pub schema: SchemaRef,
    pub batches: Vec<RecordBatch>,
    pub next_cursor: Option<usize>,
}

#[derive(Debug, Clone)]
pub struct PivotBatchResult {
    pub schema: SchemaRef,
    pub batches: Vec<RecordBatch>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PivotMetric {
    RecordCount,
    CountDistinct { field: String },
    Sum { field: String },
    Avg { field: String },
    Min { field: String },
    Max { field: String },
    Median { field: String },
    Percentile { field: String, percentile: f64 },
}

impl PivotMetric {
    pub fn count_distinct(field: impl Into<String>) -> Self {
        Self::CountDistinct {
            field: field.into(),
        }
    }

    pub fn sum(field: impl Into<String>) -> Self {
        Self::Sum {
            field: field.into(),
        }
    }

    pub fn avg(field: impl Into<String>) -> Self {
        Self::Avg {
            field: field.into(),
        }
    }

    pub fn min(field: impl Into<String>) -> Self {
        Self::Min {
            field: field.into(),
        }
    }

    pub fn max(field: impl Into<String>) -> Self {
        Self::Max {
            field: field.into(),
        }
    }

    pub fn median(field: impl Into<String>) -> Self {
        Self::Median {
            field: field.into(),
        }
    }

    pub fn percentile(field: impl Into<String>, percentile: f64) -> Result<Self, DataViewError> {
        if !percentile.is_finite() || !(0.0..=1.0).contains(&percentile) {
            return Err(DataViewError::InvalidPercentile);
        }

        Ok(Self::Percentile {
            field: field.into(),
            percentile,
        })
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::RecordCount => "record_count",
            Self::CountDistinct { .. } => "count_distinct",
            Self::Sum { .. } => "sum",
            Self::Avg { .. } => "avg",
            Self::Min { .. } => "min",
            Self::Max { .. } => "max",
            Self::Median { .. } => "median",
            Self::Percentile { .. } => "percentile",
        }
    }

    pub fn field(&self) -> Option<&str> {
        match self {
            Self::RecordCount => None,
            Self::CountDistinct { field }
            | Self::Sum { field }
            | Self::Avg { field }
            | Self::Min { field }
            | Self::Max { field }
            | Self::Median { field }
            | Self::Percentile { field, .. } => Some(field.as_str()),
        }
    }

    pub fn percentile_value(&self) -> Option<f64> {
        match self {
            Self::Percentile { percentile, .. } => Some(*percentile),
            _ => None,
        }
    }

    fn requires_numeric_measure(&self) -> Option<&str> {
        match self {
            Self::RecordCount | Self::CountDistinct { .. } => None,
            Self::Sum { field }
            | Self::Avg { field }
            | Self::Min { field }
            | Self::Max { field }
            | Self::Median { field }
            | Self::Percentile { field, .. } => Some(field.as_str()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PivotBucket {
    pub key: String,
    pub value: f64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SnapshotAccessProfile {
    allowed_columns: Vec<String>,
    masking_rules: HashMap<String, MaskingStrategy>,
}

impl SnapshotAccessProfile {
    pub fn new(allowed_columns: Vec<String>) -> Self {
        let mut deduped = Vec::new();
        for column in allowed_columns {
            if !deduped.iter().any(|existing| existing == &column) {
                deduped.push(column);
            }
        }

        Self {
            allowed_columns: deduped,
            masking_rules: HashMap::new(),
        }
    }

    pub fn with_masking_rule(
        mut self,
        field_name: impl Into<String>,
        strategy: MaskingStrategy,
    ) -> Self {
        self.masking_rules.insert(field_name.into(), strategy);
        self
    }

    fn resolve_projection(
        &self,
        available: &[String],
        requested_columns: &[String],
    ) -> Result<Vec<String>, DataViewError> {
        let allowed_available = self
            .allowed_columns
            .iter()
            .filter(|field| available.iter().any(|available| available == *field))
            .cloned()
            .collect::<Vec<_>>();

        if requested_columns.is_empty() {
            if allowed_available.is_empty() {
                return Err(DataViewError::NoAuthorizedColumns);
            }
            return Ok(allowed_available);
        }

        for column in requested_columns {
            if !self.allowed_columns.iter().any(|allowed| allowed == column) {
                return Err(DataViewError::UnauthorizedColumn(column.clone()));
            }
            if !available.iter().any(|available| available == column) {
                return Err(DataViewError::MissingColumn(column.clone()));
            }
        }

        Ok(requested_columns.to_vec())
    }

    fn mask(&self, field_name: &str, value: &str) -> String {
        let strategy = self
            .masking_rules
            .get(field_name)
            .cloned()
            .unwrap_or_else(|| recommend_field_classification(field_name).masking_strategy);
        mask_value(&strategy, value)
    }
}

#[derive(Debug)]
pub struct EncryptedSnapshotTableProvider {
    schema: SchemaRef,
    partitions: Vec<Vec<RecordBatch>>,
}

impl EncryptedSnapshotTableProvider {
    pub fn new(schema: SchemaRef, batches: Vec<RecordBatch>) -> Self {
        Self {
            schema,
            partitions: vec![batches],
        }
    }
}

#[async_trait]
impl TableProvider for EncryptedSnapshotTableProvider {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn schema(&self) -> SchemaRef {
        Arc::clone(&self.schema)
    }

    fn table_type(&self) -> TableType {
        TableType::Temporary
    }

    async fn scan(
        &self,
        _state: &dyn Session,
        projection: Option<&Vec<usize>>,
        _filters: &[Expr],
        limit: Option<usize>,
    ) -> DataFusionResult<Arc<dyn ExecutionPlan>> {
        let source = MemorySourceConfig::try_new(
            &self.partitions,
            Arc::clone(&self.schema),
            projection.cloned(),
        )?
        .with_limit(limit);

        Ok(DataSourceExec::from_data_source(source))
    }
}

pub struct EncryptedSnapshotProvider<C> {
    cipher: C,
}

impl<C> EncryptedSnapshotProvider<C>
where
    C: EnvelopeCipher,
{
    pub fn new(cipher: C) -> Self {
        Self { cipher }
    }

    pub fn decode_rows(
        &self,
        record: &EncryptedSnapshotRecord,
    ) -> Result<Vec<HashMap<String, String>>, DataViewError> {
        let batches = self.decode_record_batches(record)?;
        batches_to_rows(&batches)
    }

    pub fn columns(&self, record: &EncryptedSnapshotRecord) -> Result<Vec<String>, DataViewError> {
        if !record.columns.is_empty() {
            return Ok(record.columns.clone());
        }

        let batches = self.decode_record_batches(record)?;
        Ok(batches
            .first()
            .map(|batch| {
                batch
                    .schema()
                    .fields()
                    .iter()
                    .map(|field| field.name().to_string())
                    .collect()
            })
            .unwrap_or_default())
    }

    pub async fn read_page(
        &self,
        record: &EncryptedSnapshotRecord,
        access_profile: &SnapshotAccessProfile,
        requested_columns: &[String],
        page_size: usize,
        cursor: Option<usize>,
    ) -> Result<SnapshotPage, DataViewError> {
        let page = self
            .read_page_batches(record, access_profile, requested_columns, page_size, cursor)
            .await?;
        let rows = batches_to_rows(&page.batches)?;

        Ok(SnapshotPage {
            rows,
            next_cursor: page.next_cursor,
        })
    }

    pub async fn read_page_batches(
        &self,
        record: &EncryptedSnapshotRecord,
        access_profile: &SnapshotAccessProfile,
        requested_columns: &[String],
        page_size: usize,
        cursor: Option<usize>,
    ) -> Result<SnapshotBatchPage, DataViewError> {
        if page_size == 0 {
            return Err(DataViewError::InvalidPageSize);
        }

        let columns =
            access_profile.resolve_projection(&self.columns(record)?, requested_columns)?;
        let limit = page_size + 1;
        let offset = cursor.unwrap_or(0);
        let dataframe = self
            .table_dataframe(record, access_profile, &columns)
            .await?
            .select(column_exprs(&columns))?
            .sort(sort_exprs(&columns))?
            .limit(offset, Some(limit))?;
        let mut batches = self.collect_batches(dataframe).await?;
        let schema = batches
            .first()
            .map(|batch| batch.schema())
            .unwrap_or_else(|| empty_schema(&columns));
        let row_count = total_rows(&batches);
        let next_cursor = if row_count > page_size {
            batches = truncate_batches(batches, page_size);
            Some(offset + page_size)
        } else {
            None
        };

        Ok(SnapshotBatchPage {
            schema,
            batches,
            next_cursor,
        })
    }

    pub async fn execute_pivot(
        &self,
        record: &EncryptedSnapshotRecord,
        access_profile: &SnapshotAccessProfile,
        dimension: &str,
        metric: PivotMetric,
    ) -> Result<Vec<PivotBucket>, DataViewError> {
        let result = self
            .execute_pivot_batches(record, access_profile, dimension, metric)
            .await?;
        let rows = batches_to_rows(&result.batches)?;

        Ok(rows
            .into_iter()
            .map(|row| PivotBucket {
                key: row
                    .get("bucket_key")
                    .cloned()
                    .unwrap_or_else(|| "NULL".into()),
                value: row
                    .get("metric_value")
                    .and_then(|value| value.parse::<f64>().ok())
                    .unwrap_or_default(),
            })
            .collect())
    }

    pub async fn execute_pivot_batches(
        &self,
        record: &EncryptedSnapshotRecord,
        access_profile: &SnapshotAccessProfile,
        dimension: &str,
        metric: PivotMetric,
    ) -> Result<PivotBatchResult, DataViewError> {
        let requested_columns = pivot_requested_columns(dimension, &metric);
        access_profile.resolve_projection(&self.columns(record)?, &requested_columns)?;
        if let Some(field) = metric.requires_numeric_measure() {
            self.validate_numeric_metric_field(record, access_profile, &requested_columns, field)?;
        }
        let aggregate_expr = pivot_aggregate_expr(&metric).alias("metric_value");
        let dataframe = self
            .table_dataframe(record, access_profile, &requested_columns)
            .await?
            .select(column_exprs(&requested_columns))?
            .aggregate(vec![col(dimension)], vec![aggregate_expr])?
            .select(vec![
                col(dimension).alias("bucket_key"),
                col("metric_value"),
            ])?
            .sort(vec![col("bucket_key").sort(true, true)])?;
        let batches = self.collect_batches(dataframe).await?;
        let schema = batches
            .first()
            .map(|batch| batch.schema())
            .unwrap_or_else(pivot_output_schema);

        Ok(PivotBatchResult { schema, batches })
    }

    pub async fn execute_drilldown(
        &self,
        record: &EncryptedSnapshotRecord,
        access_profile: &SnapshotAccessProfile,
        dimension: &str,
        value: &str,
        requested_columns: &[String],
        page_size: usize,
        cursor: Option<usize>,
    ) -> Result<SnapshotPage, DataViewError> {
        if page_size == 0 {
            return Err(DataViewError::InvalidPageSize);
        }

        let mut columns = requested_columns.to_vec();
        if !columns.iter().any(|field| field == dimension) {
            columns.push(dimension.to_string());
        }
        let columns = access_profile.resolve_projection(&self.columns(record)?, &columns)?;
        let limit = page_size + 1;
        let offset = cursor.unwrap_or(0);
        let masked_value = access_profile.mask(dimension, value);
        let dataframe = self
            .table_dataframe(record, access_profile, &columns)
            .await?
            .filter(col(dimension).eq(lit(masked_value)))?
            .select(column_exprs(&columns))?
            .sort(sort_exprs(&columns))?
            .limit(offset, Some(limit))?;
        let mut rows = self.collect_rows(dataframe).await?;
        let next_cursor = if rows.len() > page_size {
            rows.truncate(page_size);
            Some(offset + page_size)
        } else {
            None
        };

        Ok(SnapshotPage { rows, next_cursor })
    }

    async fn table_dataframe(
        &self,
        record: &EncryptedSnapshotRecord,
        access_profile: &SnapshotAccessProfile,
        requested_columns: &[String],
    ) -> Result<DataFrame, DataViewError> {
        let ctx = SessionContext::new();
        ctx.register_table(
            "snapshot",
            self.table_provider(record, access_profile, requested_columns)?,
        )?;
        Ok(ctx.table("snapshot").await?)
    }

    pub fn table_provider(
        &self,
        record: &EncryptedSnapshotRecord,
        access_profile: &SnapshotAccessProfile,
        requested_columns: &[String],
    ) -> Result<Arc<EncryptedSnapshotTableProvider>, DataViewError> {
        let (batches, columns) =
            self.secure_record_batches(record, access_profile, requested_columns)?;
        let schema = batches
            .first()
            .map(|batch| batch.schema())
            .unwrap_or_else(|| empty_schema(&columns));

        Ok(Arc::new(EncryptedSnapshotTableProvider::new(
            schema, batches,
        )))
    }

    async fn collect_rows(
        &self,
        dataframe: DataFrame,
    ) -> Result<Vec<HashMap<String, String>>, DataViewError> {
        let batches = self.collect_batches(dataframe).await?;
        batches_to_rows(&batches)
    }

    async fn collect_batches(
        &self,
        dataframe: DataFrame,
    ) -> Result<Vec<RecordBatch>, DataViewError> {
        Ok(dataframe.collect().await?)
    }

    fn secure_record_batches(
        &self,
        record: &EncryptedSnapshotRecord,
        access_profile: &SnapshotAccessProfile,
        requested_columns: &[String],
    ) -> Result<(Vec<RecordBatch>, Vec<String>), DataViewError> {
        let available = self.columns(record)?;
        let columns = access_profile.resolve_projection(&available, requested_columns)?;
        let batches = self
            .decode_record_batches(record)?
            .into_iter()
            .map(|batch| {
                let arrays = columns
                    .iter()
                    .map(|column| secure_column_array(&batch, access_profile, column))
                    .collect::<Result<Vec<_>, _>>()?;
                RecordBatch::try_new(empty_schema(&columns), arrays).map_err(Into::into)
            })
            .collect::<Vec<_>>();

        batches
            .into_iter()
            .collect::<Result<Vec<_>, _>>()
            .map(|secured_batches| (secured_batches, columns))
    }

    fn validate_numeric_metric_field(
        &self,
        record: &EncryptedSnapshotRecord,
        access_profile: &SnapshotAccessProfile,
        requested_columns: &[String],
        field: &str,
    ) -> Result<(), DataViewError> {
        let (batches, _) = self.secure_record_batches(record, access_profile, requested_columns)?;
        for batch in batches {
            let Some(column_index) = schema_column_index(batch.schema().as_ref(), field) else {
                continue;
            };
            let array = batch.column(column_index).as_ref();
            for row_index in 0..batch.num_rows() {
                let value = scalar_to_string(array, row_index)?;
                if value.is_empty() {
                    continue;
                }

                if value.parse::<f64>().is_err() {
                    return Err(DataViewError::NonNumericMetricField(field.to_string()));
                }
            }
        }

        Ok(())
    }

    fn decode_record_batches(
        &self,
        record: &EncryptedSnapshotRecord,
    ) -> Result<Vec<RecordBatch>, DataViewError> {
        let plaintext = self.cipher.decrypt(&record.encrypted_payload)?;
        match record.payload_format {
            SnapshotPayloadFormat::JsonRows => {
                let decoded = serde_json::from_slice::<Vec<Vec<FieldQueryResult>>>(&plaintext)
                    .map_err(|_| DataViewError::Decode)?;
                rows_to_record_batches(&decoded, &record.columns)
            }
            SnapshotPayloadFormat::Parquet => {
                let builder = ParquetRecordBatchReaderBuilder::try_new(Bytes::from(plaintext))?;
                let reader = builder.build()?;
                let mut batches = Vec::new();
                for batch in reader {
                    batches.push(batch?);
                }
                if batches.is_empty() {
                    Ok(vec![RecordBatch::new_empty(empty_schema(&record.columns))])
                } else {
                    Ok(batches)
                }
            }
        }
    }
}

pub fn encode_rows_to_parquet(
    rows: &[Vec<FieldQueryResult>],
    projected_fields: Option<&[String]>,
) -> Result<EncodedSnapshotPayload, DataViewError> {
    let columns = resolve_columns(rows, projected_fields);
    let batches = rows_to_record_batches(rows, &columns)?;
    let schema = batches
        .first()
        .map(|batch| batch.schema())
        .unwrap_or_else(|| empty_schema(&columns));

    let mut buffer = Cursor::new(Vec::new());
    {
        let mut writer = ArrowWriter::try_new(&mut buffer, schema, None)?;
        for batch in &batches {
            writer.write(batch)?;
        }
        writer.close()?;
    }

    Ok(EncodedSnapshotPayload {
        payload: buffer.into_inner(),
        columns,
        format: SnapshotPayloadFormat::Parquet,
    })
}

pub fn encode_record_batches_to_arrow_ipc(
    schema: SchemaRef,
    batches: &[RecordBatch],
) -> Result<Vec<u8>, DataViewError> {
    let mut buffer = Cursor::new(Vec::new());
    {
        let mut writer = StreamWriter::try_new(&mut buffer, schema.as_ref())?;
        for batch in batches {
            writer.write(batch)?;
        }
        writer.finish()?;
    }
    Ok(buffer.into_inner())
}

fn rows_to_record_batches(
    rows: &[Vec<FieldQueryResult>],
    columns_hint: &[String],
) -> Result<Vec<RecordBatch>, DataViewError> {
    let columns = resolve_columns(rows, Some(columns_hint));
    let row_maps = rows
        .iter()
        .map(|row| {
            row.iter()
                .map(|field| (field.field.clone(), field.value.clone()))
                .collect::<HashMap<_, _>>()
        })
        .collect::<Vec<_>>();

    let schema = empty_schema(&columns);
    let arrays = columns
        .iter()
        .map(|column| {
            let values = row_maps
                .iter()
                .map(|row| row.get(column).cloned())
                .collect::<Vec<_>>();
            Arc::new(StringArray::from(values)) as ArrayRef
        })
        .collect::<Vec<_>>();

    Ok(vec![RecordBatch::try_new(schema, arrays)?])
}

fn resolve_columns(
    rows: &[Vec<FieldQueryResult>],
    projected_fields: Option<&[String]>,
) -> Vec<String> {
    let mut columns = Vec::new();
    if let Some(projected_fields) = projected_fields {
        for field in projected_fields {
            if !columns.contains(field) {
                columns.push(field.clone());
            }
        }
    }
    for row in rows {
        for field in row {
            if !columns.contains(&field.field) {
                columns.push(field.field.clone());
            }
        }
    }
    columns
}

fn empty_schema(columns: &[String]) -> SchemaRef {
    Arc::new(Schema::new(
        columns
            .iter()
            .map(|column| Field::new(column, DataType::Utf8, true))
            .collect::<Vec<_>>(),
    ))
}

fn pivot_output_schema() -> SchemaRef {
    Arc::new(Schema::new(vec![
        Field::new("bucket_key", DataType::Utf8, true),
        Field::new("metric_value", DataType::Float64, true),
    ]))
}

fn batches_to_rows(batches: &[RecordBatch]) -> Result<Vec<HashMap<String, String>>, DataViewError> {
    let mut rows = Vec::new();
    for batch in batches {
        let schema = batch.schema();
        for row_index in 0..batch.num_rows() {
            let mut row = HashMap::new();
            for (column_index, field) in schema.fields().iter().enumerate() {
                let value = scalar_to_string(batch.column(column_index).as_ref(), row_index)?;
                row.insert(field.name().to_string(), value);
            }
            rows.push(row);
        }
    }
    Ok(rows)
}

fn total_rows(batches: &[RecordBatch]) -> usize {
    batches.iter().map(RecordBatch::num_rows).sum()
}

fn truncate_batches(batches: Vec<RecordBatch>, limit: usize) -> Vec<RecordBatch> {
    let mut remaining = limit;
    let mut truncated = Vec::new();

    for batch in batches {
        if remaining == 0 {
            break;
        }

        if batch.num_rows() <= remaining {
            remaining -= batch.num_rows();
            truncated.push(batch);
            continue;
        }

        truncated.push(batch.slice(0, remaining));
        break;
    }

    truncated
}

fn secure_column_array(
    batch: &RecordBatch,
    access_profile: &SnapshotAccessProfile,
    column: &str,
) -> Result<ArrayRef, DataViewError> {
    let column_index = schema_column_index(batch.schema().as_ref(), column)
        .ok_or_else(|| DataViewError::MissingColumn(column.to_string()))?;
    let array = batch.column(column_index).as_ref();
    let values = (0..batch.num_rows())
        .map(|row_index| {
            scalar_to_string(array, row_index)
                .map(|value| Some(access_profile.mask(column, &value)))
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(Arc::new(StringArray::from(values)) as ArrayRef)
}

fn schema_column_index(schema: &Schema, column: &str) -> Option<usize> {
    schema
        .fields()
        .iter()
        .position(|field| field.name() == column)
}

fn scalar_to_string(array: &dyn Array, row_index: usize) -> Result<String, DataViewError> {
    if array.is_null(row_index) {
        return Ok(String::new());
    }

    match array.data_type() {
        DataType::Utf8 => Ok(array
            .as_any()
            .downcast_ref::<StringArray>()
            .expect("utf8 array")
            .value(row_index)
            .to_string()),
        DataType::LargeUtf8 => Ok(array
            .as_any()
            .downcast_ref::<LargeStringArray>()
            .expect("large utf8 array")
            .value(row_index)
            .to_string()),
        DataType::UInt64 => Ok(array
            .as_any()
            .downcast_ref::<UInt64Array>()
            .expect("u64 array")
            .value(row_index)
            .to_string()),
        DataType::UInt32 => Ok(array
            .as_any()
            .downcast_ref::<UInt32Array>()
            .expect("u32 array")
            .value(row_index)
            .to_string()),
        DataType::Int64 => Ok(array
            .as_any()
            .downcast_ref::<Int64Array>()
            .expect("i64 array")
            .value(row_index)
            .to_string()),
        DataType::Int32 => Ok(array
            .as_any()
            .downcast_ref::<Int32Array>()
            .expect("i32 array")
            .value(row_index)
            .to_string()),
        DataType::Float64 => Ok(array
            .as_any()
            .downcast_ref::<Float64Array>()
            .expect("f64 array")
            .value(row_index)
            .to_string()),
        _ => Err(DataViewError::Decode),
    }
}

fn column_exprs(columns: &[String]) -> Vec<Expr> {
    columns.iter().map(col).collect()
}

fn sort_exprs(columns: &[String]) -> Vec<SortExpr> {
    columns
        .iter()
        .map(|column| col(column).sort(true, true))
        .collect()
}

fn pivot_requested_columns(dimension: &str, metric: &PivotMetric) -> Vec<String> {
    let mut columns = vec![dimension.to_string()];
    if let Some(field) = metric.field()
        && !columns.iter().any(|column| column == field)
    {
        columns.push(field.to_string());
    }
    columns
}

fn pivot_numeric_expr(field: &str) -> Expr {
    cast(col(field), DataType::Float64)
}

fn pivot_aggregate_expr(metric: &PivotMetric) -> Expr {
    match metric {
        PivotMetric::RecordCount => count(lit(1)),
        PivotMetric::CountDistinct { field } => count_distinct(col(field)),
        PivotMetric::Sum { field } => sum(pivot_numeric_expr(field)),
        PivotMetric::Avg { field } => avg(pivot_numeric_expr(field)),
        PivotMetric::Min { field } => min(pivot_numeric_expr(field)),
        PivotMetric::Max { field } => max(pivot_numeric_expr(field)),
        PivotMetric::Median { field } => median(pivot_numeric_expr(field)),
        PivotMetric::Percentile { field, percentile } => percentile_cont(
            Sort::new(pivot_numeric_expr(field), true, true),
            lit(*percentile),
        ),
    }
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, Utc};
    use sdqp_data_classification::MaskingStrategy;
    use sdqp_encryption::{
        DevelopmentEnvelopeCipher, EnvelopeCipher, InMemorySnapshotStore, SnapshotPayloadFormat,
        SnapshotStore, SnapshotWriteRequest,
    };

    use super::{
        EncryptedSnapshotProvider, PivotMetric, SnapshotAccessProfile,
        encode_record_batches_to_arrow_ipc, encode_rows_to_parquet,
    };

    fn field_rows() -> Vec<Vec<sdqp_datasource_adapter::FieldQueryResult>> {
        vec![
            vec![
                sdqp_datasource_adapter::FieldQueryResult {
                    field: "department".into(),
                    value: "fraud".into(),
                },
                sdqp_datasource_adapter::FieldQueryResult {
                    field: "employee_id".into(),
                    value: "E-1".into(),
                },
            ],
            vec![
                sdqp_datasource_adapter::FieldQueryResult {
                    field: "department".into(),
                    value: "risk".into(),
                },
                sdqp_datasource_adapter::FieldQueryResult {
                    field: "employee_id".into(),
                    value: "E-2".into(),
                },
            ],
        ]
    }

    fn snapshot_record() -> sdqp_encryption::EncryptedSnapshotRecord {
        let cipher = DevelopmentEnvelopeCipher::new("dek-view", 0x2F);
        let encoded = encode_rows_to_parquet(&field_rows(), None).expect("parquet payload");

        let mut store = InMemorySnapshotStore::default();
        store.put(
            SnapshotWriteRequest {
                tenant_id: "tenant-alpha".into(),
                project_id: "project-alpha".into(),
                owner_user_id: "user-analyst".into(),
                grant_id: "grant-alpha".into(),
                grant_expires_at: Utc::now() + Duration::hours(8),
                retention_until: Utc::now() + Duration::hours(8),
                data_source_id: "datasource-rest".into(),
                object_bucket: "sdqp-snapshots".into(),
                data_fingerprint: "fingerprint-view".into(),
                columns: encoded.columns.clone(),
                payload_format: SnapshotPayloadFormat::Parquet,
            },
            cipher.encrypt(&encoded.payload).expect("encrypted rows"),
            field_rows().len(),
        )
    }

    fn email_rows() -> Vec<Vec<sdqp_datasource_adapter::FieldQueryResult>> {
        vec![
            vec![
                sdqp_datasource_adapter::FieldQueryResult {
                    field: "employee_email".into(),
                    value: "alice@example.com".into(),
                },
                sdqp_datasource_adapter::FieldQueryResult {
                    field: "employee_id".into(),
                    value: "E-1".into(),
                },
            ],
            vec![
                sdqp_datasource_adapter::FieldQueryResult {
                    field: "employee_email".into(),
                    value: "bob@example.com".into(),
                },
                sdqp_datasource_adapter::FieldQueryResult {
                    field: "employee_id".into(),
                    value: "E-2".into(),
                },
            ],
        ]
    }

    fn email_snapshot_record() -> sdqp_encryption::EncryptedSnapshotRecord {
        let cipher = DevelopmentEnvelopeCipher::new("dek-view", 0x2F);
        let encoded = encode_rows_to_parquet(&email_rows(), None).expect("parquet payload");

        let mut store = InMemorySnapshotStore::default();
        store.put(
            SnapshotWriteRequest {
                tenant_id: "tenant-alpha".into(),
                project_id: "project-alpha".into(),
                owner_user_id: "user-analyst".into(),
                grant_id: "grant-email".into(),
                grant_expires_at: Utc::now() + Duration::hours(8),
                retention_until: Utc::now() + Duration::hours(8),
                data_source_id: "datasource-rest".into(),
                object_bucket: "sdqp-snapshots".into(),
                data_fingerprint: "fingerprint-view-email".into(),
                columns: encoded.columns.clone(),
                payload_format: SnapshotPayloadFormat::Parquet,
            },
            cipher.encrypt(&encoded.payload).expect("encrypted rows"),
            email_rows().len(),
        )
    }

    fn numeric_rows() -> Vec<Vec<sdqp_datasource_adapter::FieldQueryResult>> {
        vec![
            vec![
                sdqp_datasource_adapter::FieldQueryResult {
                    field: "department".into(),
                    value: "fraud".into(),
                },
                sdqp_datasource_adapter::FieldQueryResult {
                    field: "case_amount".into(),
                    value: "10".into(),
                },
                sdqp_datasource_adapter::FieldQueryResult {
                    field: "employee_id".into(),
                    value: "E-1".into(),
                },
            ],
            vec![
                sdqp_datasource_adapter::FieldQueryResult {
                    field: "department".into(),
                    value: "fraud".into(),
                },
                sdqp_datasource_adapter::FieldQueryResult {
                    field: "case_amount".into(),
                    value: "20".into(),
                },
                sdqp_datasource_adapter::FieldQueryResult {
                    field: "employee_id".into(),
                    value: "E-2".into(),
                },
            ],
            vec![
                sdqp_datasource_adapter::FieldQueryResult {
                    field: "department".into(),
                    value: "risk".into(),
                },
                sdqp_datasource_adapter::FieldQueryResult {
                    field: "case_amount".into(),
                    value: "30".into(),
                },
                sdqp_datasource_adapter::FieldQueryResult {
                    field: "employee_id".into(),
                    value: "E-2".into(),
                },
            ],
        ]
    }

    fn numeric_snapshot_record() -> sdqp_encryption::EncryptedSnapshotRecord {
        let cipher = DevelopmentEnvelopeCipher::new("dek-view", 0x2F);
        let encoded = encode_rows_to_parquet(&numeric_rows(), None).expect("parquet payload");

        let mut store = InMemorySnapshotStore::default();
        store.put(
            SnapshotWriteRequest {
                tenant_id: "tenant-alpha".into(),
                project_id: "project-alpha".into(),
                owner_user_id: "user-analyst".into(),
                grant_id: "grant-numeric".into(),
                grant_expires_at: Utc::now() + Duration::hours(8),
                retention_until: Utc::now() + Duration::hours(8),
                data_source_id: "datasource-rest".into(),
                object_bucket: "sdqp-snapshots".into(),
                data_fingerprint: "fingerprint-view-numeric".into(),
                columns: encoded.columns.clone(),
                payload_format: SnapshotPayloadFormat::Parquet,
            },
            cipher.encrypt(&encoded.payload).expect("encrypted rows"),
            numeric_rows().len(),
        )
    }

    fn access_profile(columns: &[&str]) -> SnapshotAccessProfile {
        SnapshotAccessProfile::new(columns.iter().map(|column| (*column).to_string()).collect())
    }

    #[tokio::test]
    async fn encrypted_snapshot_provider_reads_paginated_rows() {
        let cipher = DevelopmentEnvelopeCipher::new("dek-view", 0x2F);
        let provider = EncryptedSnapshotProvider::new(cipher);
        let page = provider
            .read_page(
                &snapshot_record(),
                &access_profile(&["department", "employee_id"]),
                &["department".into(), "employee_id".into()],
                1,
                None,
            )
            .await
            .expect("page");

        assert_eq!(page.rows.len(), 1);
        assert_eq!(page.next_cursor, Some(1));
    }

    #[tokio::test]
    async fn pivot_execution_groups_rows_with_datafusion() {
        let cipher = DevelopmentEnvelopeCipher::new("dek-view", 0x2F);
        let provider = EncryptedSnapshotProvider::new(cipher);
        let buckets = provider
            .execute_pivot(
                &snapshot_record(),
                &access_profile(&["department"]),
                "department",
                PivotMetric::RecordCount,
            )
            .await
            .expect("pivot");

        assert_eq!(buckets.len(), 2);
        assert_eq!(buckets[0].key, "fraud");
        assert_eq!(buckets[0].value, 1.0);
    }

    #[tokio::test]
    async fn pivot_execution_supports_extended_aggregate_family() {
        let cipher = DevelopmentEnvelopeCipher::new("dek-view", 0x2F);
        let provider = EncryptedSnapshotProvider::new(cipher);
        let profile = access_profile(&["department", "case_amount", "employee_id"])
            .with_masking_rule("case_amount", MaskingStrategy::None);

        let sum_buckets = provider
            .execute_pivot(
                &numeric_snapshot_record(),
                &profile,
                "department",
                PivotMetric::sum("case_amount"),
            )
            .await
            .expect("sum pivot");
        assert_eq!(sum_buckets[0].key, "fraud");
        assert_eq!(sum_buckets[0].value, 30.0);

        let avg_buckets = provider
            .execute_pivot(
                &numeric_snapshot_record(),
                &profile,
                "department",
                PivotMetric::avg("case_amount"),
            )
            .await
            .expect("avg pivot");
        assert_eq!(avg_buckets[0].value, 15.0);

        let min_buckets = provider
            .execute_pivot(
                &numeric_snapshot_record(),
                &profile,
                "department",
                PivotMetric::min("case_amount"),
            )
            .await
            .expect("min pivot");
        assert_eq!(min_buckets[0].value, 10.0);

        let max_buckets = provider
            .execute_pivot(
                &numeric_snapshot_record(),
                &profile,
                "department",
                PivotMetric::max("case_amount"),
            )
            .await
            .expect("max pivot");
        assert_eq!(max_buckets[0].value, 20.0);

        let median_buckets = provider
            .execute_pivot(
                &numeric_snapshot_record(),
                &profile,
                "department",
                PivotMetric::median("case_amount"),
            )
            .await
            .expect("median pivot");
        assert_eq!(median_buckets[0].value, 15.0);

        let percentile_buckets = provider
            .execute_pivot(
                &numeric_snapshot_record(),
                &profile,
                "department",
                PivotMetric::percentile("case_amount", 0.75).expect("percentile"),
            )
            .await
            .expect("percentile pivot");
        assert_eq!(percentile_buckets[0].value, 17.5);

        let distinct_buckets = provider
            .execute_pivot(
                &numeric_snapshot_record(),
                &profile,
                "department",
                PivotMetric::count_distinct("employee_id"),
            )
            .await
            .expect("distinct pivot");
        assert_eq!(distinct_buckets[0].value, 2.0);
    }

    #[test]
    fn parquet_encoding_marks_payload_as_columnar_snapshot() {
        let encoded = encode_rows_to_parquet(
            &field_rows(),
            Some(&["department".into(), "employee_id".into()]),
        )
        .expect("encoded snapshot");

        assert_eq!(encoded.format, SnapshotPayloadFormat::Parquet);
        assert_eq!(
            encoded.columns,
            vec!["department".to_string(), "employee_id".to_string()]
        );
        assert!(!encoded.payload.is_empty());
    }

    #[tokio::test]
    async fn read_page_projects_only_authorized_columns_before_datafusion() {
        let provider =
            EncryptedSnapshotProvider::new(DevelopmentEnvelopeCipher::new("dek-view", 0x2F));
        let profile = SnapshotAccessProfile::new(vec!["employee_email".into()])
            .with_masking_rule("employee_email", MaskingStrategy::PartialEmail);

        let page = provider
            .read_page(&email_snapshot_record(), &profile, &[], 10, None)
            .await
            .expect("page");

        assert_eq!(page.rows.len(), 2);
        assert_eq!(
            page.rows[0].get("employee_email").map(String::as_str),
            Some("a***@example.com")
        );
        assert!(!page.rows[0].contains_key("employee_id"));
    }

    #[tokio::test]
    async fn pivot_masks_sensitive_dimensions_before_grouping() {
        let provider =
            EncryptedSnapshotProvider::new(DevelopmentEnvelopeCipher::new("dek-view", 0x2F));
        let profile = SnapshotAccessProfile::new(vec!["employee_email".into()])
            .with_masking_rule("employee_email", MaskingStrategy::PartialEmail);

        let buckets = provider
            .execute_pivot(
                &email_snapshot_record(),
                &profile,
                "employee_email",
                PivotMetric::RecordCount,
            )
            .await
            .expect("pivot");

        assert_eq!(buckets.len(), 2);
        assert!(
            buckets
                .iter()
                .any(|bucket| bucket.key == "a***@example.com")
        );
        assert!(
            buckets
                .iter()
                .any(|bucket| bucket.key == "b***@example.com")
        );
    }

    #[tokio::test]
    async fn custom_table_provider_registers_secured_arrow_batches() {
        let provider =
            EncryptedSnapshotProvider::new(DevelopmentEnvelopeCipher::new("dek-view", 0x2F));
        let profile = SnapshotAccessProfile::new(vec!["employee_email".into()])
            .with_masking_rule("employee_email", MaskingStrategy::PartialEmail);
        let table_provider = provider
            .table_provider(
                &email_snapshot_record(),
                &profile,
                &["employee_email".into()],
            )
            .expect("table provider");
        let ctx = datafusion::prelude::SessionContext::new();
        ctx.register_table("snapshot", table_provider)
            .expect("register table");

        let rows = provider
            .collect_rows(
                ctx.table("snapshot")
                    .await
                    .expect("snapshot table")
                    .select(vec![datafusion::prelude::col("employee_email")])
                    .expect("select")
                    .limit(0, Some(2))
                    .expect("limit"),
            )
            .await
            .expect("rows");

        assert_eq!(rows.len(), 2);
        assert_eq!(
            rows[0].get("employee_email").map(String::as_str),
            Some("a***@example.com")
        );
        assert!(!rows[0].contains_key("employee_id"));
    }

    #[tokio::test]
    async fn page_batches_encode_to_arrow_ipc_stream() {
        let provider =
            EncryptedSnapshotProvider::new(DevelopmentEnvelopeCipher::new("dek-view", 0x2F));
        let profile = SnapshotAccessProfile::new(vec!["employee_email".into()])
            .with_masking_rule("employee_email", MaskingStrategy::PartialEmail);
        let page = provider
            .read_page_batches(
                &email_snapshot_record(),
                &profile,
                &["employee_email".into()],
                10,
                None,
            )
            .await
            .expect("page batches");
        let encoded = encode_record_batches_to_arrow_ipc(page.schema, &page.batches)
            .expect("arrow ipc payload");
        let reader = std::io::Cursor::new(encoded);
        let mut stream =
            arrow::ipc::reader::StreamReader::try_new(reader, None).expect("stream reader");
        let batches = stream
            .by_ref()
            .collect::<Result<Vec<_>, _>>()
            .expect("decoded batches");
        let rows = super::batches_to_rows(&batches).expect("rows");

        assert_eq!(rows.len(), 2);
        assert_eq!(
            rows[0].get("employee_email").map(String::as_str),
            Some("a***@example.com")
        );
    }

    #[tokio::test]
    async fn pivot_batches_encode_to_arrow_ipc_stream() {
        let provider =
            EncryptedSnapshotProvider::new(DevelopmentEnvelopeCipher::new("dek-view", 0x2F));
        let profile = access_profile(&["department", "case_amount"])
            .with_masking_rule("case_amount", MaskingStrategy::None);
        let result = provider
            .execute_pivot_batches(
                &numeric_snapshot_record(),
                &profile,
                "department",
                PivotMetric::sum("case_amount"),
            )
            .await
            .expect("pivot batches");
        let encoded = encode_record_batches_to_arrow_ipc(result.schema, &result.batches)
            .expect("arrow ipc payload");
        let reader = std::io::Cursor::new(encoded);
        let mut stream =
            arrow::ipc::reader::StreamReader::try_new(reader, None).expect("stream reader");
        let batches = stream
            .by_ref()
            .collect::<Result<Vec<_>, _>>()
            .expect("decoded batches");
        let rows = super::batches_to_rows(&batches).expect("rows");

        assert!(rows.iter().any(|row| {
            row.get("bucket_key").map(String::as_str) == Some("fraud")
                && row.get("metric_value").map(String::as_str) == Some("30")
        }));
    }

    #[tokio::test]
    async fn numeric_pivot_rejects_masked_non_numeric_measure_fields() {
        let provider =
            EncryptedSnapshotProvider::new(DevelopmentEnvelopeCipher::new("dek-view", 0x2F));
        let profile = SnapshotAccessProfile::new(vec!["employee_email".into()])
            .with_masking_rule("employee_email", MaskingStrategy::PartialEmail);

        let error = provider
            .execute_pivot(
                &email_snapshot_record(),
                &profile,
                "employee_email",
                PivotMetric::avg("employee_email"),
            )
            .await
            .expect_err("non-numeric measure");

        assert!(matches!(
            error,
            super::DataViewError::NonNumericMetricField(field) if field == "employee_email"
        ));
    }

    #[tokio::test]
    async fn read_page_rejects_unauthorized_requested_columns() {
        let provider =
            EncryptedSnapshotProvider::new(DevelopmentEnvelopeCipher::new("dek-view", 0x2F));
        let profile = SnapshotAccessProfile::new(vec!["employee_email".into()])
            .with_masking_rule("employee_email", MaskingStrategy::PartialEmail);

        let error = provider
            .read_page(
                &email_snapshot_record(),
                &profile,
                &["employee_id".into()],
                10,
                None,
            )
            .await
            .expect_err("unauthorized");

        assert!(matches!(
            error,
            super::DataViewError::UnauthorizedColumn(column) if column == "employee_id"
        ));
    }
}
