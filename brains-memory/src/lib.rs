use serde::{Serialize, Deserialize};
use chrono::Utc;
use uuid::Uuid;
use std::collections::HashMap;

#[derive(Debug, Serialize, Deserialize)]
pub struct MemoryEntry {
    pub id: Uuid,
    pub problem: String,
    pub solution: String,
    pub category: Option<String>,
    pub created_at: chrono::DateTime<Utc>,
    pub investigator_id: String,
    pub case_id: String,
}

impl MemoryEntry {
    pub fn new(
        problem: String,
        solution: String,
        category: Option<String>,
        investigator_id: String,
        case_id: String,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            problem,
            solution,
            category,
            created_at: Utc::now(),
            investigator_id,
            case_id,
        }
    }

    pub fn summary(&self) -> String {
        format!("{}: {}...", 
            self.category.as_deref().unwrap_or("uncategorized"),
            self.problem.chars().take(40).collect::<String>()
        )
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct MemoryStore {
    entries: HashMap<Uuid, MemoryEntry>,
}

impl MemoryStore {
    pub fn load_or_create(path: &std::path::Path) -> anyhow::Result<Self> {
        if path.exists() {
            let content = std::fs::read_to_string(path)?;
            Ok(serde_json::from_str(&content)?)
        } else {
            Ok(Self::default())
        }
    }

    pub fn save(&self, path: &std::path::Path) -> anyhow::Result<()> {
        let content = serde_json::to_string_pretty(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }

    pub fn add(&mut self, entry: MemoryEntry) -> anyhow::Result<()> {
        self.entries.insert(entry.id, entry);
        Ok(())
    }

    pub fn search(&self, query: &str, min_score: f64) -> anyhow::Result<Vec<(f64, &MemoryEntry)>> {
        let mut results = Vec::new();
        for entry in self.entries.values() {
            let score = if entry.problem.contains(query) || entry.solution.contains(query) {
                1.0
            } else {
                0.0
            };
            if score >= min_score {
                results.push((score, entry));
            }
        }
        results.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap());
        Ok(results)
    }

    pub fn list(&self, category: Option<&str>) -> anyhow::Result<Vec<&MemoryEntry>> {
        Ok(self.entries.values()
            .filter(|e| category.map_or(true, |c| e.category.as_deref() == Some(c)))
            .collect())
    }
}