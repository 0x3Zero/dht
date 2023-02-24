#![allow(improper_ctypes)]

mod dht;
mod ed25519;
mod record;
mod result;
mod secp256k1;

use marine_rs_sdk::marine;
use marine_rs_sdk::module_manifest;
use marine_rs_sdk::WasmLoggerBuilder;

use dht::FdbDht;
use ed25519::verify as verify_ed25519;
use marine_sqlite_connector::{Connection, Error, Result};
use record::Record;
use result::FdbResult;
use secp256k1::verify as verify_secp256k1;

module_manifest!();

const DEFAULT_PATH: &str = "dht";
const DEFAULT_ENC: &str = "secp256k1";

pub fn main() {
    WasmLoggerBuilder::new()
        .with_log_level(log::LevelFilter::Info)
        .build()
        .unwrap();
}

#[marine]
pub fn verify_signature(
    public_key: String,
    signature: String,
    message: String,
    enc: String,
) -> bool {
    let verify: bool;
    if enc.is_empty() || enc == DEFAULT_ENC {
        verify = verify_secp256k1(public_key.clone(), signature, message);
    } else {
        verify = verify_ed25519(public_key.clone(), signature, message);
    }

    verify
}

#[marine]
pub fn initialize() -> FdbResult {
    let conn = get_connection(DEFAULT_PATH);
    let res = create_dht_table(&conn);
    FdbResult::from_res(res)
}

#[marine]
pub fn shutdown() -> FdbResult {
    let conn = get_connection(DEFAULT_PATH);
    let res = delete_dht_table(&conn);
    FdbResult::from_res(res)
}

#[marine]
pub fn insert(
    data_key: String,
    alias: String,
    cid: String,
    public_key: String,
    signature: String,
    message: String,
    enc: String,
) -> FdbResult {
    let verify: bool;
    let enc_verify: String;

    if enc.is_empty() || enc == DEFAULT_ENC {
        verify = verify_secp256k1(public_key.clone(), signature, message);
        enc_verify = DEFAULT_ENC.to_string();
    } else {
        verify = verify_ed25519(public_key.clone(), signature, message);
        enc_verify = enc;
    }

    if !verify {
        return FdbResult::from_err_str("You are not the owner!");
    }

    let conn = get_connection(DEFAULT_PATH);

    // Check if PK and key exist
    let checker;
    log::info!("{}", alias.is_empty());
    if alias.is_empty() {
        checker = get_record_by_pk_and_key(&conn, data_key.clone(), public_key.clone());
    } else {
        checker = get_record_by_pk_key_and_alias(
            &conn,
            data_key.clone(),
            public_key.clone(),
            alias.clone(),
        );
    }
    match checker {
        Ok(value) => {
            let res;
            if value.is_none() {
                res = add_record(&conn, data_key, alias, public_key, cid, enc_verify);
            } else {
                res = update_record(&conn, data_key, alias, public_key, cid);
            }
            FdbResult::from_res(res)
        }
        Err(err) => FdbResult::from_err_str(&err.message.unwrap()),
    }
}

#[marine]
pub fn get_records_by_key(key: String) -> Vec<FdbDht> {
    let conn = get_connection(DEFAULT_PATH);
    let records = get_records(&conn, key).unwrap();

    log::info!("{:?}", records);

    let mut dhts = Vec::new();

    for record in records.iter() {
        match record {
            _ => dhts.push(FdbDht {
                public_key: record.public_key.clone(),
                alias: record.alias.clone(),
                cid: record.cid.clone(),
                data_key: record.data_key.clone(),
            }),
        }
    }

    dhts
}

#[marine]
pub fn get_latest_record_by_pk_and_key(key: String, public_key: String) -> FdbDht {
    let conn = get_connection(DEFAULT_PATH);
    let record = get_record_by_pk_and_key(&conn, key, public_key).unwrap();

    let mut fdb = FdbDht {
        ..Default::default()
    };

    if !record.is_none() {
        let r = record.unwrap();
        fdb.public_key = r.public_key.clone();
        fdb.cid = r.cid.clone();
        fdb.data_key = r.data_key.clone();
        fdb.alias = r.alias.clone()
    }

    fdb
}

/************************ *********************/

pub fn get_connection(db_name: &str) -> Connection {
    let path = format!("tmp/{}_db.sqlite", db_name);
    Connection::open(&path).unwrap()
}

pub fn get_none_error() -> Error {
    Error {
        code: None,
        message: Some("Value doesn't exist".to_string()),
    }
}

pub fn create_dht_table(conn: &Connection) -> Result<()> {
    conn.execute(
        "
  create table if not exists dht (
          uuid INTEGER not null primary key AUTOINCREMENT,
          data_key TEXT not null,
          alias varchar(255) not null,
          cid TEXT not null,
          owner_pk TEXT not null,
          enc varchar(20) not null
      );
  ",
    )?;

    Ok(())
}

pub fn delete_dht_table(conn: &Connection) -> Result<()> {
    conn.execute(
        "
  drop table if exists dht;
  ",
    )?;

    Ok(())
}

pub fn add_record(
    conn: &Connection,
    data_key: String,
    alias: String,
    owner_pk: String,
    cid: String,
    enc: String,
) -> Result<()> {
    conn.execute(format!(
        "insert into dht (data_key, alias, cid, owner_pk, enc) values ('{}', '{}', '{}', '{}', '{}');",
        data_key, alias, cid, owner_pk, enc
    ))?;

    log::info!(
        "insert into dht (data_key, alias, cid, owner_pk, enc) values ('{}', '{}', '{}', '{}', '{}');",
        data_key, alias, cid, owner_pk, enc
    );

    Ok(())
}

// pub fn get_all_dht_records(conn: &Connection) -> Result<Vec<Record>> {
//     let mut cursor = conn.prepare("select * from dht;")?.cursor();

//     let mut records = Vec::new();
//     while let Some(row) = cursor.next()? {
//         records.push(Record::from_row(row)?);
//     }

//     Ok(records)
// }

pub fn update_record(
    conn: &Connection,
    data_key: String,
    alias: String,
    owner_pk: String,
    cid: String,
) -> Result<()> {
    conn.execute(format!(
        "
      update dht
      set alias = '{}',
      cid = '{}'
      where owner_pk = '{}' AND data_key = '{}';
      ",
        alias, cid, owner_pk, data_key
    ))?;

    Ok(())
}

pub fn get_exact_record(conn: &Connection, key: String, pk: String) -> Result<Record> {
    read_execute(
        conn,
        format!(
            "select * from dht where data_key = '{}' AND owner_pk = '{}';",
            key, pk
        ),
    )
}

pub fn get_records(conn: &Connection, key: String) -> Result<Vec<Record>> {
    let mut cursor = conn
        .prepare(format!("select * from dht where data_key = '{}'", key))?
        .cursor();

    let mut records = Vec::new();

    while let Some(row) = cursor.next()? {
        records.push(Record::from_row(row)?);
    }

    Ok(records)
}

pub fn get_record_by_field(conn: &Connection, field: String, pk: String) -> Result<Option<Record>> {
    let mut cursor = conn
        .prepare(format!("select * from dht where {} = '{}';", field, pk))?
        .cursor();

    let row = cursor.next()?;
    if row != None {
        let found_record = Record::from_row(row.unwrap());
        Ok(Some(found_record.unwrap()))
    } else {
        Ok(None)
    }
}

pub fn get_record_by_pk_and_key(
    conn: &Connection,
    key: String,
    pk: String,
) -> Result<Option<Record>> {
    let mut cursor = conn
        .prepare(format!(
            "select * from dht where owner_pk = '{}' AND data_key = '{}';",
            pk, key
        ))?
        .cursor();

    let row = cursor.next()?;
    if row != None {
        let found_record = Record::from_row(row.unwrap());
        Ok(Some(found_record.unwrap()))
    } else {
        Ok(None)
    }
}

pub fn get_record_by_pk_key_and_alias(
    conn: &Connection,
    key: String,
    pk: String,
    name: String,
) -> Result<Option<Record>> {
    let mut cursor = conn
        .prepare(format!(
            "select * from dht where owner_pk = '{}' AND data_key = '{}' AND alias = '{}';",
            pk, key, name
        ))?
        .cursor();

    let row = cursor.next()?;
    if row != None {
        let found_record = Record::from_row(row.unwrap());
        Ok(Some(found_record.unwrap()))
    } else {
        Ok(None)
    }
}

fn read_execute(conn: &Connection, statement: String) -> Result<Record> {
    let mut cursor = conn.prepare(statement)?.cursor();
    let row = cursor.next()?.ok_or(get_none_error());
    let found_record = Record::from_row(row.unwrap_or_default());
    Ok(found_record?)
}
