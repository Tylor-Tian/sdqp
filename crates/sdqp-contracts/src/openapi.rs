use serde_json::{Value, json};

use crate::proto::PROTO_PACKAGES;

pub fn build_openapi_document() -> Value {
    json!({
        "openapi": "3.1.0",
        "info": {
            "title": "SDQP REST API",
            "version": "v1",
            "description": "Phase 2 generated REST contract snapshot for the SDQP local verification stack."
        },
        "x-sdqp-grpc-services": [
            {
                "name": "WatermarkDetectionService",
                "package": "sdqp.watermark.v1",
                "entrypoint": "sdqp-watermark-grpc",
                "description": "Standalone gRPC boundary for external DLP and leak-detection systems to detect, verify, and batch scan SDQP watermarks.",
                "methods": [
                    "DetectWatermarks",
                    "VerifyWatermark",
                    "BatchScan",
                    "EvaluateDlpPolicy"
                ]
            }
        ],
        "paths": {
            "/healthz": {
                "get": {
                    "operationId": "healthCheck",
                    "responses": {
                        "200": {
                            "description": "Service health payload",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/ServiceHealth"}
                                }
                            }
                        }
                    }
                }
            },
            "/readyz": {
                "get": {
                    "operationId": "readinessCheck",
                    "responses": {
                        "200": {
                            "description": "Service readiness payload",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/ServiceHealth"}
                                }
                            }
                        }
                    }
                }
            },
            "/metrics": {
                "get": {
                    "operationId": "metricsSnapshot",
                    "responses": {
                        "200": {
                            "description": "Prometheus metrics text output"
                        }
                    }
                }
            },
            "/auth/login": {
                "post": {
                    "operationId": "login",
                    "responses": {"200": {"description": "Pending MFA session issued"}}
                }
            },
            "/auth/sso/start": {
                "post": {
                    "operationId": "startSso",
                    "responses": {"200": {"description": "Mock SSO authorization initiated"}}
                }
            },
            "/auth/sso/callback": {
                "post": {
                    "operationId": "completeSso",
                    "responses": {"200": {"description": "SSO callback converted into pending MFA session"}}
                }
            },
            "/auth/mfa/verify": {
                "post": {
                    "operationId": "verifyMfa",
                    "responses": {"200": {"description": "Token pair issued"}}
                }
            },
            "/auth/device-posture": {
                "post": {
                    "operationId": "reportDevicePosture",
                    "responses": {"200": {"description": "Continuous authentication risk evaluation"}}
                }
            },
            "/auth/step-up/verify": {
                "post": {
                    "operationId": "verifyStepUp",
                    "responses": {"200": {"description": "Step-up verification cleared and tokens re-issued"}}
                }
            },
            "/auth/refresh": {
                "post": {
                    "operationId": "refreshToken",
                    "responses": {"200": {"description": "Refreshed access token"}}
                }
            },
            "/auth/logout": {
                "post": {
                    "operationId": "logout",
                    "responses": {"200": {"description": "Refresh token revoked"}}
                }
            },
            "/auth/scim/users": {
                "post": {
                    "operationId": "syncScimUser",
                    "responses": {"200": {"description": "SCIM user synchronization accepted"}}
                }
            },
            "/auth/scim/groups": {
                "post": {
                    "operationId": "syncScimGroup",
                    "responses": {"200": {"description": "SCIM group synchronization accepted"}}
                }
            },
            "/auth/scim/sync": {
                "post": {
                    "operationId": "runScimProviderSync",
                    "responses": {"200": {"description": "SCIM provider pull synchronization completed with lifecycle plan and cursor"}}
                }
            },
            "/v1/queries": {
                "post": {
                    "operationId": "submitQuery",
                    "responses": {"200": {"description": "Async query task created"}}
                }
            },
            "/v1/permissions/applications": {
                "post": {
                    "operationId": "submitPermissionApplication",
                    "responses": {"200": {"description": "Permission application submitted"}}
                }
            },
            "/v1/permissions/grants": {
                "get": {
                    "operationId": "listPermissionGrants",
                    "responses": {"200": {"description": "Current user grants in the active project"}}
                }
            },
            "/v1/approvals/tasks": {
                "get": {
                    "operationId": "listApprovalTasks",
                    "responses": {"200": {"description": "Pending approval tasks for the current approver"}}
                }
            },
            "/v1/approvals/callback": {
                "post": {
                    "operationId": "submitApprovalAction",
                    "responses": {"200": {"description": "Approval action applied"}}
                }
            },
            "/v1/approvals/approver-resolution": {
                "post": {
                    "operationId": "resolveEffectiveApprover",
                    "responses": {"200": {"description": "Provider-neutral approver availability, delegation, and escalation resolution"}}
                }
            },
            "/v1/tasks/{task_id}/status": {
                "get": {
                    "operationId": "queryTaskStatus",
                    "responses": {"200": {"description": "Query task status"}}
                }
            },
            "/v1/classification/catalog/{data_source_id}": {
                "get": {
                    "operationId": "classificationCatalog",
                    "responses": {
                        "200": {
                            "description": "Project/data-source scoped active classification catalog with regulation and retention metadata",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/ClassificationCatalogResponse"}
                                }
                            }
                        }
                    }
                }
            },
            "/v1/classification/rule-versions/{data_source_id}": {
                "get": {
                    "operationId": "listClassificationRuleVersions",
                    "responses": {
                        "200": {
                            "description": "Classification rule-version governance list for the active project and data source",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/ClassificationRuleVersionsResponse"}
                                }
                            }
                        }
                    }
                },
                "post": {
                    "operationId": "createClassificationRuleVersion",
                    "requestBody": {
                        "required": true,
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/CreateClassificationRuleVersionRequest"}
                            }
                        }
                    },
                    "responses": {
                        "201": {
                            "description": "Draft classification rule version created with derived catalog metadata",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/ClassificationRuleVersionResponse"}
                                }
                            }
                        }
                    }
                }
            },
            "/v1/classification/rule-versions/{data_source_id}/{rule_version_id}/activate": {
                "post": {
                    "operationId": "activateClassificationRuleVersion",
                    "responses": {
                        "200": {
                            "description": "Classification rule version activated and previous active version retired",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/ClassificationRuleVersionResponse"}
                                }
                            }
                        }
                    }
                }
            },
            "/v1/classification/rule-versions/{data_source_id}/{rule_version_id}/retire": {
                "post": {
                    "operationId": "retireClassificationRuleVersion",
                    "responses": {
                        "200": {
                            "description": "Classification rule version retired",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/ClassificationRuleVersionResponse"}
                                }
                            }
                        }
                    }
                }
            },
            "/v1/classification/policies/{data_source_id}": {
                "get": {
                    "operationId": "listClassificationPolicies",
                    "responses": {
                        "200": {
                            "description": "Runtime field classification policies with governing rule-version, category, regulation, and retention metadata",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/ClassificationPoliciesResponse"}
                                }
                            }
                        }
                    }
                }
            },
            "/v1/classification/policies/{data_source_id}/confirm": {
                "post": {
                    "operationId": "confirmClassificationPolicies",
                    "requestBody": {
                        "required": true,
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/ConfirmClassificationRequest"}
                            }
                        }
                    },
                    "responses": {
                        "200": {
                            "description": "Manual classification confirmation bound to a rule version and catalog metadata",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/ClassificationPoliciesResponse"}
                                }
                            }
                        }
                    }
                }
            },
            "/v1/snapshots/{snapshot_id}/page": {
                "get": {
                    "operationId": "snapshotPage",
                    "parameters": [
                        {
                            "name": "page_size",
                            "in": "query",
                            "schema": {"type": "integer", "minimum": 1}
                        },
                        {
                            "name": "cursor",
                            "in": "query",
                            "schema": {"type": "integer", "minimum": 0}
                        },
                        {
                            "name": "response_format",
                            "in": "query",
                            "schema": {"$ref": "#/components/schemas/AnalysisResponseFormat"}
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "Snapshot detail page",
                            "headers": {
                                "x-sdqp-response-meta": {
                                    "description": "Base64-encoded JSON metadata for Arrow IPC responses.",
                                    "schema": {"type": "string"}
                                }
                            },
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/SnapshotPageResponse"}
                                },
                                "application/vnd.apache.arrow.stream": {
                                    "schema": {"type": "string", "format": "binary"}
                                }
                            }
                        }
                    }
                }
            },
            "/v1/analysis/pivot": {
                "post": {
                    "operationId": "pivotAnalysis",
                    "requestBody": {
                        "required": true,
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/PivotAnalysisRequest"}
                            }
                        }
                    },
                    "responses": {
                        "200": {
                            "description": "Pivot analysis response",
                            "headers": {
                                "x-sdqp-response-meta": {
                                    "description": "Base64-encoded JSON metadata for Arrow IPC responses.",
                                    "schema": {"type": "string"}
                                }
                            },
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/PivotAnalysisResponse"}
                                },
                                "application/vnd.apache.arrow.stream": {
                                    "schema": {"type": "string", "format": "binary"}
                                }
                            }
                        }
                    }
                }
            },
            "/v1/analysis/pivot/drilldown": {
                "post": {
                    "operationId": "pivotDrilldown",
                    "responses": {"200": {"description": "Drilldown page response"}}
                }
            },
            "/v1/analysis/templates": {
                "get": {
                    "operationId": "listAnalysisTemplates",
                    "responses": {
                        "200": {
                            "description": "Analysis templates visible to the current user in the active project",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/AnalysisTemplateListResponse"}
                                }
                            }
                        }
                    }
                },
                "post": {
                    "operationId": "createAnalysisTemplate",
                    "requestBody": {
                        "required": true,
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/AnalysisTemplateUpsertRequest"}
                            }
                        }
                    },
                    "responses": {
                        "201": {
                            "description": "Analysis template created",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/AnalysisTemplateResponse"}
                                }
                            }
                        }
                    }
                }
            },
            "/v1/analysis/templates/{template_id}": {
                "get": {
                    "operationId": "getAnalysisTemplate",
                    "responses": {
                        "200": {
                            "description": "Analysis template details",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/AnalysisTemplateResponse"}
                                }
                            }
                        }
                    }
                },
                "put": {
                    "operationId": "updateAnalysisTemplate",
                    "requestBody": {
                        "required": true,
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/AnalysisTemplateUpsertRequest"}
                            }
                        }
                    },
                    "responses": {
                        "200": {
                            "description": "Analysis template updated",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/AnalysisTemplateResponse"}
                                }
                            }
                        }
                    }
                },
                "delete": {
                    "operationId": "deleteAnalysisTemplate",
                    "responses": {
                        "200": {
                            "description": "Analysis template deleted",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/AnalysisTemplateDeleteResponse"}
                                }
                            }
                        }
                    }
                }
            },
            "/v1/analysis/templates/{template_id}/publish": {
                "post": {
                    "operationId": "publishAnalysisTemplate",
                    "responses": {
                        "200": {
                            "description": "Analysis template published to the active project",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/AnalysisTemplateResponse"}
                                }
                            }
                        }
                    }
                }
            },
            "/v1/analysis/templates/{template_id}/unpublish": {
                "post": {
                    "operationId": "unpublishAnalysisTemplate",
                    "responses": {
                        "200": {
                            "description": "Analysis template returned to owner-private scope",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/AnalysisTemplateResponse"}
                                }
                            }
                        }
                    }
                }
            },
            "/v1/audit/events/search": {
                "get": {
                    "operationId": "auditSearch",
                    "responses": {"200": {"description": "Audit search results"}}
                }
            },
            "/v1/exports/evidence": {
                "post": {
                    "operationId": "exportEvidencePackage",
                    "requestBody": {
                        "required": true,
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/EvidenceExportRequest"}
                            }
                        }
                    },
                    "responses": {
                        "200": {
                            "description": "Evidence export task created",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/EvidenceExportResponse"}
                                }
                            }
                        }
                    }
                }
            },
            "/v1/exports/tasks/{task_id}": {
                "get": {
                    "operationId": "exportTaskStatus",
                    "responses": {
                        "200": {
                            "description": "Evidence export task status",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/EvidenceExportResponse"}
                                }
                            }
                        }
                    }
                }
            },
            "/v1/exports/tasks/{task_id}/refresh-anchor": {
                "post": {
                    "operationId": "refreshEvidenceAnchor",
                    "responses": {
                        "200": {
                            "description": "Evidence anchor receipt refreshed and verification state recalculated",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/EvidenceExportResponse"}
                                }
                            }
                        }
                    }
                }
            },
            "/v1/exports/tasks/{task_id}/authorize-download": {
                "post": {
                    "operationId": "authorizeEvidenceDownload",
                    "requestBody": {
                        "required": true,
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/ExportDownloadAuthorizationRequest"}
                            }
                        }
                    },
                    "responses": {
                        "200": {
                            "description": "One-time download authorization issued",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/ExportDownloadAuthorizationResponse"}
                                }
                            }
                        },
                        "409": {"description": "Evidence certification is not completed"}
                    }
                }
            },
            "/v1/exports/download/{download_token}": {
                "get": {
                    "operationId": "downloadEvidencePackage",
                    "responses": {"200": {"description": "Evidence package payload download"}}
                }
            },
            "/v1/watermarks/dlp/evaluate": {
                "post": {
                    "operationId": "evaluateWatermarkDlpPolicy",
                    "requestBody": {
                        "required": true,
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/DlpPolicyEvaluateRequest"}
                            }
                        }
                    },
                    "responses": {
                        "200": {
                            "description": "Watermark detection plus DLP provider policy decision",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/DlpPolicyEvaluateResponse"}
                                }
                            }
                        }
                    }
                }
            },
            "/v1/projects": {
                "get": {
                    "operationId": "listProjects",
                    "responses": {"200": {"description": "Tenant project catalog"}}
                }
            },
            "/v1/projects/{project_id}/state": {
                "post": {
                    "operationId": "updateProjectState",
                    "responses": {"200": {"description": "Project lifecycle transitioned"}}
                }
            },
            "/v1/admin/config-drift": {
                "get": {
                    "operationId": "configDrift",
                    "responses": {"200": {"description": "Config drift report"}}
                }
            },
            "/v1/admin/credential-rotations": {
                "get": {
                    "operationId": "listCredentialRotationStates",
                    "responses": {"200": {"description": "Credential rotation policy/state view including last and next due timestamps"}}
                }
            },
            "/v1/admin/credential-rotations/run": {
                "post": {
                    "operationId": "runCredentialRotation",
                    "responses": {"200": {"description": "Runs due credential rotation automation for repo-local integration credentials and records audit events"}}
                }
            },
            "/v1/ueba/alerts": {
                "get": {
                    "operationId": "uebaAlerts",
                    "responses": {"200": {"description": "UEBA alert list"}}
                }
            },
            "/v1/ueba/baselines": {
                "get": {
                    "operationId": "uebaBaselines",
                    "responses": {"200": {"description": "UEBA user and entity baselines"}}
                }
            },
            "/v1/ueba/rules": {
                "get": {
                    "operationId": "uebaGovernanceRules",
                    "responses": {"200": {"description": "UEBA governance rule versions, separate from alert and baseline observability"}}
                },
                "post": {
                    "operationId": "createUebaGovernanceRule",
                    "responses": {"201": {"description": "Created UEBA governance rule version"}}
                }
            },
            "/v1/ueba/rules/{rule_version_id}/activate": {
                "post": {
                    "operationId": "activateUebaGovernanceRule",
                    "responses": {"200": {"description": "Activated a UEBA governance rule version and retired the previous active version"}}
                }
            },
            "/v1/ueba/rules/{rule_version_id}/enable": {
                "post": {
                    "operationId": "enableUebaGovernanceRule",
                    "responses": {"200": {"description": "Enabled a non-retired UEBA governance rule version"}}
                }
            },
            "/v1/ueba/rules/{rule_version_id}/disable": {
                "post": {
                    "operationId": "disableUebaGovernanceRule",
                    "responses": {"200": {"description": "Disabled a UEBA governance rule version without deleting its history"}}
                }
            },
            "/v1/ueba/rules/{rule_version_id}/retire": {
                "post": {
                    "operationId": "retireUebaGovernanceRule",
                    "responses": {"200": {"description": "Retired a UEBA governance rule version"}}
                }
            },
            "/v1/ueba/rules/{rule_version_id}/tune": {
                "post": {
                    "operationId": "tuneUebaGovernanceRule",
                    "responses": {"200": {"description": "Created a tuned UEBA governance rule version"}}
                }
            },
            "/v1/ueba/replays": {
                "post": {
                    "operationId": "createUebaReplay",
                    "responses": {"200": {"description": "Replayed persisted audit events through selected UEBA governance rule versions"}}
                }
            },
            "/v1/ueba/replays/{run_id}": {
                "get": {
                    "operationId": "getUebaReplay",
                    "responses": {"200": {"description": "Loaded a persisted UEBA replay run"}}
                }
            },
            "/v1/ueba/tuning/proposals": {
                "post": {
                    "operationId": "createUebaTuningProposal",
                    "responses": {"201": {"description": "Created a replay-backed UEBA tuning proposal"}}
                }
            },
            "/v1/ueba/tuning/proposals/{proposal_id}/apply": {
                "post": {
                    "operationId": "applyUebaTuningProposal",
                    "responses": {"200": {"description": "Applied a UEBA tuning proposal as a new rule version"}}
                }
            },
            "/v1/ueba/calibrations": {
                "post": {
                    "operationId": "createUebaCalibration",
                    "responses": {"200": {"description": "Closed UEBA calibration using repo-local audit samples and deterministic recommendations"}}
                }
            },
            "/v1/ueba/calibrations/{calibration_id}": {
                "get": {
                    "operationId": "getUebaCalibration",
                    "responses": {"200": {"description": "Loaded a persisted UEBA calibration run"}}
                }
            },
            "/v1/worker/project-queue": {
                "get": {
                    "operationId": "workerProjectQueue",
                    "responses": {"200": {"description": "Worker queue scope inspection"}}
                }
            }
        },
        "components": {
            "schemas": {
                "AnalysisResponseFormat": {
                    "type": "string",
                    "enum": ["json", "arrow_ipc"]
                },
                "ServiceHealth": {
                    "type": "object",
                    "required": ["service", "status", "phase", "details"],
                    "properties": {
                        "service": {"type": "string"},
                        "status": {"type": "string"},
                        "phase": {"type": "string"},
                        "details": {
                            "type": "object",
                            "additionalProperties": {"type": "string"}
                        }
                    }
                },
                "RegulationReference": {
                    "type": "object",
                    "required": ["code", "jurisdiction", "title", "retention_basis"],
                    "properties": {
                        "code": {"type": "string"},
                        "jurisdiction": {"type": "string"},
                        "title": {"type": "string"},
                        "retention_basis": {"type": "string"}
                    }
                },
                "RetentionPolicy": {
                    "type": "object",
                    "required": ["policy_id", "retain_for_days", "disposal_action", "legal_hold_supported"],
                    "properties": {
                        "policy_id": {"type": "string"},
                        "retain_for_days": {"type": "integer"},
                        "disposal_action": {"type": "string", "enum": ["review", "archive", "purge", "Review", "Archive", "Purge"]},
                        "legal_hold_supported": {"type": "boolean"}
                    }
                },
                "ClassificationCatalogEntry": {
                    "type": "object",
                    "required": [
                        "catalog_entry_id",
                        "data_category",
                        "level",
                        "applicable_regulations",
                        "retention_policy",
                        "manual_confirmation_required",
                        "rule_ids"
                    ],
                    "properties": {
                        "catalog_entry_id": {"type": "string"},
                        "data_category": {
                            "type": "string",
                            "enum": [
                                "public_reference",
                                "internal_operational",
                                "personal_contact",
                                "personal_identifier",
                                "financial_identifier",
                                "investigation_sensitive",
                                "general_confidential"
                            ]
                        },
                        "level": {"type": "string"},
                        "applicable_regulations": {
                            "type": "array",
                            "items": {"$ref": "#/components/schemas/RegulationReference"}
                        },
                        "retention_policy": {"$ref": "#/components/schemas/RetentionPolicy"},
                        "manual_confirmation_required": {"type": "boolean"},
                        "rule_ids": {
                            "type": "array",
                            "items": {"type": "string"}
                        }
                    }
                },
                "ClassificationRule": {
                    "type": "object",
                    "required": [
                        "rule_id",
                        "field_matchers",
                        "sample_patterns",
                        "level",
                        "masking_strategy",
                        "watermark_strength"
                    ],
                    "properties": {
                        "rule_id": {"type": "string"},
                        "catalog_entry_id": {"type": "string"},
                        "field_matchers": {
                            "type": "array",
                            "items": {"type": "string"}
                        },
                        "sample_patterns": {
                            "type": "array",
                            "items": {"type": "string"}
                        },
                        "level": {"type": "string", "enum": ["L1Public", "L2Internal", "L3Confidential", "L4Sensitive", "L5Restricted"]},
                        "data_category": {"type": "string"},
                        "applicable_regulations": {
                            "type": "array",
                            "items": {"$ref": "#/components/schemas/RegulationReference"}
                        },
                        "retention_policy": {"$ref": "#/components/schemas/RetentionPolicy"},
                        "manual_confirmation_required": {"type": "boolean"},
                        "masking_strategy": {"type": "string", "enum": ["None", "PartialEmail", "PartialPhone", "Full"]},
                        "watermark_strength": {"type": "string", "enum": ["Low", "Medium", "High", "Critical"]}
                    }
                },
                "ClassificationRuleVersionResponse": {
                    "type": "object",
                    "required": [
                        "rule_version_id",
                        "project_id",
                        "data_source_id",
                        "version_number",
                        "status",
                        "rules",
                        "catalog_entries"
                    ],
                    "properties": {
                        "rule_version_id": {"type": "string"},
                        "project_id": {"type": "string"},
                        "data_source_id": {"type": "string"},
                        "version_number": {"type": "integer"},
                        "status": {"type": "string", "enum": ["draft", "active", "retired"]},
                        "rules": {
                            "type": "array",
                            "items": {"$ref": "#/components/schemas/ClassificationRule"}
                        },
                        "catalog_entries": {
                            "type": "array",
                            "items": {"$ref": "#/components/schemas/ClassificationCatalogEntry"}
                        }
                    }
                },
                "ClassificationRuleVersionsResponse": {
                    "type": "object",
                    "required": ["data_source_id", "versions"],
                    "properties": {
                        "data_source_id": {"type": "string"},
                        "active_rule_version_id": {"type": ["string", "null"]},
                        "versions": {
                            "type": "array",
                            "items": {"$ref": "#/components/schemas/ClassificationRuleVersionResponse"}
                        }
                    }
                },
                "CreateClassificationRuleVersionRequest": {
                    "type": "object",
                    "required": ["rules"],
                    "properties": {
                        "description": {"type": ["string", "null"]},
                        "rules": {
                            "type": "array",
                            "items": {"$ref": "#/components/schemas/ClassificationRule"}
                        }
                    }
                },
                "ClassificationCatalogResponse": {
                    "type": "object",
                    "required": ["project_id", "data_source_id", "active_rule_version_id", "entries"],
                    "properties": {
                        "project_id": {"type": "string"},
                        "data_source_id": {"type": "string"},
                        "active_rule_version_id": {"type": "string"},
                        "entries": {
                            "type": "array",
                            "items": {"$ref": "#/components/schemas/ClassificationCatalogEntry"}
                        }
                    }
                },
                "ClassificationPolicyResponse": {
                    "type": "object",
                    "required": [
                        "field_name",
                        "level",
                        "data_category",
                        "status",
                        "masking_strategy",
                        "watermark_strength",
                        "source",
                        "applicable_regulations",
                        "retention_policy",
                        "manual_confirmation_required"
                    ],
                    "properties": {
                        "field_name": {"type": "string"},
                        "level": {"type": "string"},
                        "data_category": {"type": "string"},
                        "status": {"type": "string", "enum": ["pending_confirmation", "confirmed"]},
                        "masking_strategy": {"type": "string"},
                        "watermark_strength": {"type": "string"},
                        "source": {"type": "string", "enum": ["rule_engine", "sample_detection", "manual_confirmation"]},
                        "sample_value": {"type": ["string", "null"]},
                        "rule_version_id": {"type": ["string", "null"]},
                        "detection_run_id": {"type": ["string", "null"]},
                        "catalog_entry_id": {"type": ["string", "null"]},
                        "applicable_regulations": {
                            "type": "array",
                            "items": {"$ref": "#/components/schemas/RegulationReference"}
                        },
                        "retention_policy": {"$ref": "#/components/schemas/RetentionPolicy"},
                        "manual_confirmation_required": {"type": "boolean"}
                    }
                },
                "ClassificationPoliciesResponse": {
                    "type": "object",
                    "required": ["data_source_id", "policies"],
                    "properties": {
                        "data_source_id": {"type": "string"},
                        "policies": {
                            "type": "array",
                            "items": {"$ref": "#/components/schemas/ClassificationPolicyResponse"}
                        }
                    }
                },
                "ConfirmClassificationRequest": {
                    "type": "object",
                    "required": ["fields"],
                    "properties": {
                        "fields": {
                            "type": "array",
                            "items": {"type": "string"}
                        },
                        "rule_version_id": {"type": ["string", "null"]},
                        "reviewer_note": {"type": ["string", "null"]}
                    }
                },
                "FieldDisplayPolicyResponse": {
                    "type": "object",
                    "required": ["field_name", "masked", "render_mode", "watermark_strength"],
                    "properties": {
                        "field_name": {"type": "string"},
                        "masked": {"type": "boolean"},
                        "render_mode": {"type": "string"},
                        "watermark_strength": {"type": "string"}
                    }
                },
                "SnapshotPageResponse": {
                    "type": "object",
                    "required": [
                        "snapshot_id",
                        "columns",
                        "rows",
                        "field_policies",
                        "watermark_text"
                    ],
                    "properties": {
                        "snapshot_id": {"type": "string"},
                        "columns": {
                            "type": "array",
                            "items": {"type": "string"}
                        },
                        "rows": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "additionalProperties": {"type": "string"}
                            }
                        },
                        "next_cursor": {"type": ["integer", "null"]},
                        "field_policies": {
                            "type": "array",
                            "items": {"$ref": "#/components/schemas/FieldDisplayPolicyResponse"}
                        },
                        "watermark_text": {"type": "string"}
                    }
                },
                "PivotAnalysisRequest": {
                    "type": "object",
                    "required": ["snapshot_id", "dimension"],
                    "properties": {
                        "snapshot_id": {"type": "string"},
                        "dimension": {"type": "string"},
                        "metric": {
                            "type": "string",
                            "enum": [
                                "record_count",
                                "count_distinct",
                                "sum",
                                "avg",
                                "min",
                                "max",
                                "median",
                                "percentile"
                            ]
                        },
                        "metric_field": {"type": "string"},
                        "percentile": {"type": "number"},
                        "response_format": {"$ref": "#/components/schemas/AnalysisResponseFormat"}
                    }
                },
                "PivotBucket": {
                    "type": "object",
                    "required": ["key", "value"],
                    "properties": {
                        "key": {"type": "string"},
                        "value": {"type": "number"}
                    }
                },
                "PivotAnalysisResponse": {
                    "type": "object",
                    "required": ["snapshot_id", "dimension", "metric", "buckets", "watermark_text"],
                    "properties": {
                        "snapshot_id": {"type": "string"},
                        "dimension": {"type": "string"},
                        "metric": {"type": "string"},
                        "metric_field": {"type": ["string", "null"]},
                        "percentile": {"type": ["number", "null"]},
                        "buckets": {
                            "type": "array",
                            "items": {"$ref": "#/components/schemas/PivotBucket"}
                        },
                        "watermark_text": {"type": "string"}
                    }
                },
                "AnalysisTemplateVisibility": {
                    "type": "string",
                    "enum": ["private", "published"]
                },
                "AnalysisTemplateConfig": {
                    "type": "object",
                    "required": ["detail_fields", "pivot_dimension", "pivot_metric"],
                    "properties": {
                        "page_size": {"type": ["integer", "null"], "minimum": 1},
                        "detail_fields": {
                            "type": "array",
                            "items": {"type": "string"}
                        },
                        "pivot_dimension": {"type": "string"},
                        "pivot_metric": {
                            "type": "string",
                            "enum": [
                                "record_count",
                                "count_distinct",
                                "sum",
                                "avg",
                                "min",
                                "max",
                                "median",
                                "percentile"
                            ]
                        },
                        "pivot_metric_field": {"type": ["string", "null"]},
                        "pivot_percentile": {"type": ["number", "null"]}
                    }
                },
                "AnalysisTemplateUpsertRequest": {
                    "type": "object",
                    "required": ["name", "data_source_id", "config"],
                    "properties": {
                        "name": {"type": "string"},
                        "description": {"type": ["string", "null"]},
                        "data_source_id": {"type": "string"},
                        "config": {"$ref": "#/components/schemas/AnalysisTemplateConfig"}
                    }
                },
                "AnalysisTemplateResponse": {
                    "type": "object",
                    "required": [
                        "template_id",
                        "name",
                        "data_source_id",
                        "visibility",
                        "owner_user_id",
                        "editable",
                        "created_at",
                        "updated_at",
                        "config"
                    ],
                    "properties": {
                        "template_id": {"type": "string"},
                        "name": {"type": "string"},
                        "description": {"type": ["string", "null"]},
                        "data_source_id": {"type": "string"},
                        "visibility": {"$ref": "#/components/schemas/AnalysisTemplateVisibility"},
                        "owner_user_id": {"type": "string"},
                        "editable": {"type": "boolean"},
                        "published_at": {"type": ["string", "null"], "format": "date-time"},
                        "created_at": {"type": "string", "format": "date-time"},
                        "updated_at": {"type": "string", "format": "date-time"},
                        "config": {"$ref": "#/components/schemas/AnalysisTemplateConfig"}
                    }
                },
                "AnalysisTemplateListResponse": {
                    "type": "object",
                    "required": ["templates"],
                    "properties": {
                        "templates": {
                            "type": "array",
                            "items": {"$ref": "#/components/schemas/AnalysisTemplateResponse"}
                        }
                    }
                },
                "DlpRequestScope": {
                    "type": "object",
                    "required": ["tenant_id", "project_id", "user_id"],
                    "properties": {
                        "tenant_id": {"type": "string"},
                        "project_id": {"type": "string"},
                        "user_id": {"type": "string"}
                    }
                },
                "DlpInspectionContext": {
                    "type": "object",
                    "required": ["caller_system", "policy_id", "source_uri", "correlation_id"],
                    "properties": {
                        "caller_system": {"type": "string"},
                        "policy_id": {"type": "string"},
                        "source_uri": {"type": "string"},
                        "correlation_id": {"type": "string"},
                        "scope": {"$ref": "#/components/schemas/DlpRequestScope"},
                        "attributes": {
                            "type": "object",
                            "additionalProperties": {"type": "string"}
                        }
                    }
                },
                "DlpProviderConfig": {
                    "type": "object",
                    "required": ["provider_kind"],
                    "properties": {
                        "provider_id": {"type": ["string", "null"]},
                        "provider_kind": {
                            "type": "string",
                            "enum": ["local-policy", "webhook"]
                        },
                        "webhook_url": {"type": ["string", "null"]},
                        "auth_header": {"type": ["string", "null"]},
                        "auth_token": {"type": ["string", "null"]},
                        "timeout_ms": {"type": ["integer", "null"], "minimum": 1},
                        "default_action": {
                            "type": ["string", "null"],
                            "enum": ["allow", "alert", "quarantine", "block", "escalate", "unspecified"]
                        },
                        "attributes": {
                            "type": "object",
                            "additionalProperties": {"type": "string"}
                        }
                    }
                },
                "DlpPolicyEvaluateRequest": {
                    "type": "object",
                    "required": ["document_id", "inspection_context"],
                    "properties": {
                        "document_id": {"type": "string"},
                        "content": {"type": ["string", "null"]},
                        "content_base64": {"type": ["string", "null"]},
                        "content_format": {
                            "type": ["string", "null"],
                            "enum": ["text", "pdf", "office", "image", "binary"]
                        },
                        "media_type": {"type": ["string", "null"]},
                        "expected_token": {"type": ["string", "null"]},
                        "include_payload": {"type": "boolean"},
                        "inspection_context": {"$ref": "#/components/schemas/DlpInspectionContext"},
                        "provider_config": {"$ref": "#/components/schemas/DlpProviderConfig"}
                    }
                },
                "DlpDetectionSummary": {
                    "type": "object",
                    "required": [
                        "watermark_present",
                        "verified",
                        "algorithm_verified",
                        "match_count",
                        "algorithm_match_count",
                        "carrier_match_count",
                        "legacy_match_count",
                        "expected_token_matched"
                    ],
                    "properties": {
                        "watermark_present": {"type": "boolean"},
                        "verified": {"type": "boolean"},
                        "algorithm_verified": {"type": "boolean"},
                        "match_count": {"type": "integer"},
                        "algorithm_match_count": {"type": "integer"},
                        "carrier_match_count": {"type": "integer"},
                        "legacy_match_count": {"type": "integer"},
                        "expected_token_matched": {"type": "boolean"}
                    }
                },
                "DlpPolicyDecision": {
                    "type": "object",
                    "required": [
                        "provider_id",
                        "provider_kind",
                        "policy_id",
                        "policy_version",
                        "disposition",
                        "action",
                        "callback_delivered",
                        "enforcement_required",
                        "reasons",
                        "attributes",
                        "enforcement_ttl_seconds"
                    ],
                    "properties": {
                        "provider_id": {"type": "string"},
                        "provider_kind": {"type": "string"},
                        "policy_id": {"type": "string"},
                        "policy_version": {"type": "string"},
                        "disposition": {"type": "string"},
                        "action": {"type": "string"},
                        "callback_delivered": {"type": "boolean"},
                        "enforcement_required": {"type": "boolean"},
                        "reasons": {
                            "type": "array",
                            "items": {"type": "string"}
                        },
                        "attributes": {
                            "type": "object",
                            "additionalProperties": {"type": "string"}
                        },
                        "enforcement_ttl_seconds": {"type": "integer"}
                    }
                },
                "DlpPolicyEvaluateResponse": {
                    "type": "object",
                    "required": [
                        "scan_id",
                        "document_id",
                        "inspection_context",
                        "matches",
                        "disposition",
                        "decision"
                    ],
                    "properties": {
                        "scan_id": {"type": "string"},
                        "document_id": {"type": "string"},
                        "inspection_context": {"$ref": "#/components/schemas/DlpInspectionContext"},
                        "matches": {
                            "type": "array",
                            "items": {"type": "object"}
                        },
                        "summary": {"$ref": "#/components/schemas/DlpDetectionSummary"},
                        "disposition": {"type": "string"},
                        "decision": {"$ref": "#/components/schemas/DlpPolicyDecision"}
                    }
                },
                "EvidenceTemplate": {
                    "type": "string",
                    "enum": ["china-judicial", "eu-regulatory", "us-litigation"]
                },
                "EvidenceTaskStatus": {
                    "type": "string",
                    "enum": ["completed", "pending_anchor", "failed_anchor", "failed"]
                },
                "EvidenceVerificationStatus": {
                    "type": "string",
                    "enum": ["verified", "pending_anchor", "failed_anchor", "invalid"]
                },
                "EvidenceExportRequest": {
                    "type": "object",
                    "required": ["snapshot_id", "template"],
                    "properties": {
                        "snapshot_id": {"type": "string"},
                        "template": {"$ref": "#/components/schemas/EvidenceTemplate"},
                        "export_body": {"type": ["string", "null"]}
                    }
                },
                "EvidenceExportResponse": {
                    "type": "object",
                    "required": [
                        "task_id",
                        "status",
                        "verified",
                        "integrity_verified",
                        "verification_status",
                        "package_id",
                        "snapshot_id",
                        "template",
                        "jurisdiction",
                        "watermark_token",
                        "audit_chain_valid",
                        "hash_chain_digest",
                        "timestamp_provider",
                        "timestamp_runtime_mode",
                        "anchor_provider",
                        "anchor_runtime_mode",
                        "anchor_status",
                        "anchor_network",
                        "provider_runtime_mode",
                        "external_final_uat_required",
                        "refresh_recommended",
                        "recipient_user_id",
                        "manifest_digest",
                        "verification_ready",
                        "download_ready",
                        "created_at"
                    ],
                    "properties": {
                        "task_id": {"type": "string"},
                        "status": {"$ref": "#/components/schemas/EvidenceTaskStatus"},
                        "verified": {"type": "boolean"},
                        "integrity_verified": {"type": "boolean"},
                        "verification_status": {"$ref": "#/components/schemas/EvidenceVerificationStatus"},
                        "package_id": {"type": "string"},
                        "snapshot_id": {"type": "string"},
                        "template": {"$ref": "#/components/schemas/EvidenceTemplate"},
                        "jurisdiction": {"type": "string"},
                        "watermark_token": {"type": "string"},
                        "watermark_text": {"type": "string"},
                        "exported_document": {"type": "string"},
                        "audit_event_count": {"type": "integer"},
                        "audit_chain_valid": {"type": "boolean"},
                        "hash_chain_digest": {"type": "string"},
                        "timestamp_provider": {"type": "string"},
                        "timestamp_runtime_mode": {"type": "string", "enum": ["mock", "repo_local", "external", "unknown"]},
                        "timestamp_authority": {"type": "string"},
                        "timestamp_token": {"type": "string"},
                        "anchor_provider": {"type": "string"},
                        "anchor_runtime_mode": {"type": "string", "enum": ["mock", "repo_local", "external", "unknown"]},
                        "anchor_status": {"type": "string", "enum": ["pending", "confirmed", "failed"]},
                        "anchor_network": {"type": "string"},
                        "anchor_transaction_id": {"type": "string"},
                        "anchor_block_number": {"type": ["integer", "null"]},
                        "anchor_confirmed_at": {"type": ["string", "null"], "format": "date-time"},
                        "anchor_failure_reason": {"type": ["string", "null"]},
                        "provider_runtime_mode": {"type": "string", "enum": ["mock", "repo_local", "external", "unknown"]},
                        "external_final_uat_required": {"type": "boolean"},
                        "mock_provider_components": {
                            "type": "array",
                            "items": {"type": "string"}
                        },
                        "refresh_recommended": {"type": "boolean"},
                        "recipient_user_id": {"type": "string"},
                        "data_payload_kms_provider": {"type": "string"},
                        "data_payload_dek_id": {"type": "string"},
                        "data_payload_scope_binding": {"type": "string"},
                        "audit_extract_event_count": {"type": "integer"},
                        "certificate_title": {"type": "string"},
                        "certificate_issued_at": {"type": "string", "format": "date-time"},
                        "manifest_digest": {"type": "string"},
                        "verification_ready": {"type": "boolean"},
                        "file_name": {"type": "string"},
                        "media_type": {"type": "string"},
                        "download_ready": {"type": "boolean"},
                        "created_at": {"type": "string", "format": "date-time"},
                        "completed_at": {"type": ["string", "null"], "format": "date-time"},
                        "last_anchor_refresh_at": {"type": ["string", "null"], "format": "date-time"},
                        "failure_reason": {"type": ["string", "null"]}
                    }
                },
                "ExportDownloadAuthorizationRequest": {
                    "type": "object",
                    "properties": {
                        "ttl_seconds": {"type": ["integer", "null"], "minimum": 60, "maximum": 3600}
                    }
                },
                "ExportDownloadAuthorizationResponse": {
                    "type": "object",
                    "required": ["task_id", "download_token", "file_name", "media_type", "expires_at"],
                    "properties": {
                        "task_id": {"type": "string"},
                        "download_token": {"type": "string"},
                        "file_name": {"type": "string"},
                        "media_type": {"type": "string"},
                        "expires_at": {"type": "string", "format": "date-time"}
                    }
                },
                "AnalysisTemplateDeleteResponse": {
                    "type": "object",
                    "required": ["template_id", "deleted"],
                    "properties": {
                        "template_id": {"type": "string"},
                        "deleted": {"type": "boolean"}
                    }
                }
            }
        }
    })
}

pub fn build_proto_contract_index() -> Value {
    json!({
        "version": 1,
        "contracts": PROTO_PACKAGES
            .iter()
            .map(|(file, package)| json!({ "file": file, "package": package }))
            .collect::<Vec<_>>()
    })
}
