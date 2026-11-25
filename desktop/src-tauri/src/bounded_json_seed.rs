//! SAME bounded strict JSON visitor used by original protocol and closed metadata IPC.
//! Mechanical move only; no decoder selection, IO, or public parser API.
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use std::{collections::BTreeSet, fmt};
pub(crate) struct Seed<'a> {
    pub(crate) nodes: &'a mut usize,
    pub(crate) depth: usize,
    pub(crate) node_limit: usize,
    pub(crate) depth_limit: usize,
}
impl<'de> DeserializeSeed<'de> for Seed<'_> {
    type Value = Value;
    fn deserialize<D: de::Deserializer<'de>>(self, deserializer: D) -> Result<Value, D::Error> {
        *self.nodes += 1;
        if *self.nodes > self.node_limit || self.depth > self.depth_limit {
            return Err(de::Error::custom("JSON bounds exceeded"));
        }
        deserializer.deserialize_any(self)
    }
}
impl<'de> Visitor<'de> for Seed<'_> {
    type Value = Value;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("bounded strict JSON")
    }
    fn visit_bool<E: de::Error>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }
    fn visit_i64<E: de::Error>(self, v: i64) -> Result<Value, E> {
        Ok(Value::Number(v.into()))
    }
    fn visit_u64<E: de::Error>(self, v: u64) -> Result<Value, E> {
        Ok(Value::Number(v.into()))
    }
    fn visit_f64<E: de::Error>(self, v: f64) -> Result<Value, E> {
        Number::from_f64(v)
            .map(Value::Number)
            .ok_or_else(|| de::Error::custom("nonfinite number"))
    }
    fn visit_str<E: de::Error>(self, v: &str) -> Result<Value, E> {
        Ok(Value::String(v.to_owned()))
    }
    fn visit_string<E: de::Error>(self, v: String) -> Result<Value, E> {
        Ok(Value::String(v))
    }
    fn visit_unit<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_none<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        if self.depth >= self.depth_limit {
            return Err(de::Error::custom("container nesting exceeded"));
        }
        let mut items = Vec::new();
        while let Some(value) = seq.next_element_seed(Seed {
            nodes: self.nodes,
            depth: self.depth + 1,
            node_limit: self.node_limit,
            depth_limit: self.depth_limit,
        })? {
            items.push(value);
        }
        Ok(Value::Array(items))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        if self.depth >= self.depth_limit {
            return Err(de::Error::custom("container nesting exceeded"));
        }
        let mut items = Map::new();
        let mut names = BTreeSet::new();
        while let Some(key) = map.next_key::<String>()? {
            *self.nodes += 1;
            if *self.nodes > self.node_limit || self.depth + 1 > self.depth_limit {
                return Err(de::Error::custom("JSON bounds exceeded"));
            }
            if !names.insert(key.clone()) {
                return Err(de::Error::custom("duplicate JSON key"));
            }
            let value = map.next_value_seed(Seed {
                nodes: self.nodes,
                depth: self.depth + 1,
                node_limit: self.node_limit,
                depth_limit: self.depth_limit,
            })?;
            items.insert(key, value);
        }
        Ok(Value::Object(items))
    }
}
