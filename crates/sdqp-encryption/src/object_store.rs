use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use bytes::Bytes;
use object_store::{ObjectStore, ObjectStoreExt, aws::AmazonS3Builder, path::Path};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotObjectMetadata {
    pub bucket: String,
    pub key: String,
    pub size_bytes: usize,
}

#[derive(Debug, Error)]
pub enum SnapshotObjectStoreError {
    #[error("object store client build failed: {0}")]
    Build(String),
    #[error("object store operation failed: {0}")]
    Operation(String),
    #[error("object payload encoding is invalid")]
    InvalidEncoding,
}

#[async_trait]
pub trait SnapshotObjectStore: Send + Sync {
    async fn put_ciphertext(
        &self,
        bucket: &str,
        key: &str,
        ciphertext_b64: &str,
    ) -> Result<SnapshotObjectMetadata, SnapshotObjectStoreError>;

    async fn get_ciphertext(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<String, SnapshotObjectStoreError>;

    async fn delete_object(&self, bucket: &str, key: &str) -> Result<(), SnapshotObjectStoreError>;

    async fn exists(&self, bucket: &str, key: &str) -> Result<bool, SnapshotObjectStoreError>;
}

#[derive(Debug, Default)]
pub struct InMemorySnapshotObjectStore {
    objects: Mutex<HashMap<String, Vec<u8>>>,
}

#[async_trait]
impl SnapshotObjectStore for InMemorySnapshotObjectStore {
    async fn put_ciphertext(
        &self,
        bucket: &str,
        key: &str,
        ciphertext_b64: &str,
    ) -> Result<SnapshotObjectMetadata, SnapshotObjectStoreError> {
        let decoded = STANDARD
            .decode(ciphertext_b64.as_bytes())
            .map_err(|_| SnapshotObjectStoreError::InvalidEncoding)?;
        self.objects
            .lock()
            .expect("object store")
            .insert(format!("{bucket}/{key}"), decoded.clone());
        Ok(SnapshotObjectMetadata {
            bucket: bucket.to_string(),
            key: key.to_string(),
            size_bytes: decoded.len(),
        })
    }

    async fn get_ciphertext(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<String, SnapshotObjectStoreError> {
        let object = self
            .objects
            .lock()
            .expect("object store")
            .get(&format!("{bucket}/{key}"))
            .cloned()
            .ok_or_else(|| SnapshotObjectStoreError::Operation("object not found".into()))?;
        Ok(STANDARD.encode(object))
    }

    async fn delete_object(&self, bucket: &str, key: &str) -> Result<(), SnapshotObjectStoreError> {
        self.objects
            .lock()
            .expect("object store")
            .remove(&format!("{bucket}/{key}"));
        Ok(())
    }

    async fn exists(&self, bucket: &str, key: &str) -> Result<bool, SnapshotObjectStoreError> {
        Ok(self
            .objects
            .lock()
            .expect("object store")
            .contains_key(&format!("{bucket}/{key}")))
    }
}

#[derive(Debug, Clone)]
pub struct S3CompatibleObjectStore {
    endpoint: String,
    region: String,
    access_key: String,
    secret_key: String,
}

impl S3CompatibleObjectStore {
    pub fn new(
        endpoint: impl Into<String>,
        region: impl Into<String>,
        access_key: impl Into<String>,
        secret_key: impl Into<String>,
    ) -> Self {
        Self {
            endpoint: endpoint.into(),
            region: region.into(),
            access_key: access_key.into(),
            secret_key: secret_key.into(),
        }
    }

    fn store(&self, bucket: &str) -> Result<Arc<dyn ObjectStore>, SnapshotObjectStoreError> {
        let store = AmazonS3Builder::new()
            .with_bucket_name(bucket)
            .with_endpoint(self.endpoint.clone())
            .with_region(self.region.clone())
            .with_access_key_id(self.access_key.clone())
            .with_secret_access_key(self.secret_key.clone())
            .with_allow_http(true)
            .build()
            .map_err(|error| SnapshotObjectStoreError::Build(error.to_string()))?;
        Ok(Arc::new(store))
    }
}

#[async_trait]
impl SnapshotObjectStore for S3CompatibleObjectStore {
    async fn put_ciphertext(
        &self,
        bucket: &str,
        key: &str,
        ciphertext_b64: &str,
    ) -> Result<SnapshotObjectMetadata, SnapshotObjectStoreError> {
        let decoded = STANDARD
            .decode(ciphertext_b64.as_bytes())
            .map_err(|_| SnapshotObjectStoreError::InvalidEncoding)?;
        let store = self.store(bucket)?;
        let path = Path::from(key);
        store
            .put(&path, Bytes::from(decoded.clone()).into())
            .await
            .map_err(|error| SnapshotObjectStoreError::Operation(error.to_string()))?;
        Ok(SnapshotObjectMetadata {
            bucket: bucket.to_string(),
            key: key.to_string(),
            size_bytes: decoded.len(),
        })
    }

    async fn get_ciphertext(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<String, SnapshotObjectStoreError> {
        let store = self.store(bucket)?;
        let path = Path::from(key);
        let payload = store
            .get(&path)
            .await
            .map_err(|error| SnapshotObjectStoreError::Operation(error.to_string()))?
            .bytes()
            .await
            .map_err(|error| SnapshotObjectStoreError::Operation(error.to_string()))?;
        Ok(STANDARD.encode(payload))
    }

    async fn delete_object(&self, bucket: &str, key: &str) -> Result<(), SnapshotObjectStoreError> {
        let store = self.store(bucket)?;
        let path = Path::from(key);
        store
            .delete(&path)
            .await
            .map_err(|error| SnapshotObjectStoreError::Operation(error.to_string()))?;
        Ok(())
    }

    async fn exists(&self, bucket: &str, key: &str) -> Result<bool, SnapshotObjectStoreError> {
        let store = self.store(bucket)?;
        let path = Path::from(key);
        match store.get(&path).await {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{InMemorySnapshotObjectStore, SnapshotObjectStore};

    #[tokio::test]
    async fn in_memory_object_store_round_trips_ciphertext() {
        let store = InMemorySnapshotObjectStore::default();
        let metadata = store
            .put_ciphertext("snapshots", "tenant-a/object.enc", "AQID")
            .await
            .expect("stored");
        assert_eq!(metadata.size_bytes, 3);
        assert!(
            store
                .exists("snapshots", "tenant-a/object.enc")
                .await
                .expect("exists")
        );
        assert_eq!(
            store
                .get_ciphertext("snapshots", "tenant-a/object.enc")
                .await
                .expect("payload"),
            "AQID"
        );
    }
}
