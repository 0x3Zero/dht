use marine_rs_sdk::marine;
use marine_sqlite_connector::{Error, Result, Value};

pub fn get_none_error() -> Error {
    Error {
        code: None,
        message: Some("Value doesn't exist".to_string()),
    }
}

#[marine]
#[derive(Default, PartialEq, Debug)]
pub struct Record {
    pub uuid: i64,
    pub data_key: String,
    pub alias: String,
    pub cid: String,
    pub public_key: String,
    pub enc: String,
    pub err_msg: String,
    pub success: bool,
}

impl Record {
    pub fn from_row(row: &[Value]) -> Result<Record> {
        let row_record = Record {
            uuid: row[0].as_integer().ok_or(get_none_error())?,
            data_key: row[1].as_string().ok_or(get_none_error())?.to_string(),
            alias: row[2].as_string().unwrap_or_default().to_string(),
            cid: row[3].as_string().ok_or(get_none_error())?.to_string(),
            public_key: row[4].as_string().ok_or(get_none_error())?.to_string(),
            enc: row[5].as_string().ok_or(get_none_error())?.to_string(),
            err_msg: "".to_string(),
            success: true,
            ..Default::default()
        };

        Ok(row_record)
    }

    pub fn from_res(res: Result<Record>) -> Record {
        match res {
            Ok(v) => v,
            Err(e) => {
                let mut res_data: Record = Default::default();
                res_data.err_msg = e.to_string();
                res_data.success = false;
                res_data
            }
        }
    }
}
