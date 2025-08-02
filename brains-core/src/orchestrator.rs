use crate::AnalysisInput;
use brains_detection::{DetectionResult, PatternEngine};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

#[derive(Debug, Clone)]
pub struct EngineOrchestrator {
    semaphore: Arc<Semaphore>,
    timeout: Duration,
}

#[derive(Debug, thiserror::Error)]
pub enum ExecError {
    #[error("Engine execution timeout")]
    Timeout,
    #[error("Engine panic: {0}")]
    EnginePanic(String),
    #[error("Analysis error: {0}")]
    Analysis(#[from] anyhow::Error),
    #[error("Join error: {0}")]
    Join(#[from] tokio::task::JoinError),
}

impl EngineOrchestrator {
    pub fn new(max_concurrent: usize, timeout: Duration) -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(max_concurrent)),
            timeout,
        }
    }

    pub async fn execute(
        &self,
        engine: Arc<dyn PatternEngine + Send + Sync>,
        input: AnalysisInput,
    ) -> Result<Vec<DetectionResult>, ExecError> {
        let _permit = self.semaphore.acquire().await?;
        
        let code = match input {
            AnalysisInput::SourceCode { content, .. } => content,
            AnalysisInput::BinaryData { data, .. } => String::from_utf8_lossy(&data).to_string(),
            AnalysisInput::LogEntries { entries, .. } => entries.join("\n"),
            _ => return Err(ExecError::Analysis(anyhow::anyhow!("Unsupported input type"))),
        };
        
        let task = tokio::spawn(async move {
            engine.analyze(&code)
        });
        
        let result = tokio::time::timeout(self.timeout, task).await;
        
        match result {
            Ok(Ok(analysis_result)) => analysis_result.map_err(ExecError::Analysis),
            Ok(Err(join_error)) => Err(ExecError::Join(join_error)),
            Err(_) => Err(ExecError::Timeout),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use brains_detection::{BasicLLMDetector, PatternEngine};
    use std::time::Duration;

    #[tokio::test]
    async fn test_orchestrator_execution() {
        let orchestrator = EngineOrchestrator::new(2, Duration::from_secs(5));
        let engine: Arc<dyn PatternEngine + Send + Sync> = Arc::new(BasicLLMDetector::new());
        
        let input = AnalysisInput::SourceCode {
            content: "fn main() {}".to_string(),
            language: "rust".to_string(),
            file_path: None,
        };
        
        let result = orchestrator.execute(engine, input).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_timeout_enforcement() {
        let orchestrator = EngineOrchestrator::new(1, Duration::from_millis(1));
        let engine: Arc<dyn PatternEngine + Send + Sync> = Arc::new(BasicLLMDetector::new());
        
        let input = AnalysisInput::SourceCode {
            content: "fn main() {}".to_string(),
            language: "rust".to_string(),
            file_path: None,
        };
        
        let result = orchestrator.execute(engine, input).await;
        match result {
            Err(ExecError::Timeout) => {},
            _ => panic!("Expected timeout error"),
        }
    }
}