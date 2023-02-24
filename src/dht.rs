use eyre::Result;
use marine_rs_sdk::marine;

#[marine]
#[derive(Debug, Default)]
pub struct FdbDht {
    pub public_key: String,
    pub alias: String,
    pub cid: String,
    pub data_key: String,
}

#[marine]
pub struct DhtsGetResult {
    pub success: bool,
    pub error: String,
    pub datas: Vec<FdbDht>,
}

impl From<Result<Vec<FdbDht>>> for DhtsGetResult {
    fn from(result: Result<Vec<FdbDht>>) -> Self {
        match result {
            Ok(datas) => Self {
                success: true,
                error: "".to_string(),
                datas,
            },
            Err(err) => Self {
                success: false,
                error: err.to_string(),
                datas: Vec::new(),
            },
        }
    }
}

#[marine]
pub struct DhtGetResult {
    pub success: bool,
    pub error: String,
    pub data: FdbDht,
}

impl From<Result<FdbDht>> for DhtGetResult {
    fn from(result: Result<FdbDht>) -> Self {
        match result {
            Ok(data) => Self {
                success: true,
                error: "".to_string(),
                data,
            },
            Err(err) => Self {
                success: false,
                error: err.to_string(),
                data: FdbDht {
                    public_key: "".to_string(),
                    alias: "".to_string(),
                    cid: "".to_string(),
                    data_key: "".to_string(),
                },
            },
        }
    }
}
