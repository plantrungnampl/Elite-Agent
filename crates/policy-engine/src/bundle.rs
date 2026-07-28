use std::collections::BTreeSet;

use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::Value;

use crate::{invalid_input, sha256_digest, PolicyBundleV1, Sha256Digest};

pub(crate) fn parse_bundle(raw: &str) -> Result<(PolicyBundleV1, Sha256Digest), crate::PortError> {
    let mut deserializer = serde_json::Deserializer::from_str(raw);
    RejectDuplicateKeys
        .deserialize(&mut deserializer)
        .map_err(|_| invalid_input())?;
    deserializer.end().map_err(|_| invalid_input())?;

    let value: Value = serde_json::from_str(raw).map_err(|_| invalid_input())?;
    let bundle: PolicyBundleV1 =
        serde_json::from_value(value.clone()).map_err(|_| invalid_input())?;
    bundle.validate()?;
    let canonical = serde_json_canonicalizer::to_vec(&value).map_err(|_| invalid_input())?;
    let digest = Sha256Digest::new(sha256_digest(&canonical)).map_err(|_| invalid_input())?;
    Ok((bundle, digest))
}

struct RejectDuplicateKeys;

impl<'de> DeserializeSeed<'de> for RejectDuplicateKeys {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<(), D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(RejectDuplicateKeysVisitor)
    }
}

struct RejectDuplicateKeysVisitor;

impl<'de> Visitor<'de> for RejectDuplicateKeysVisitor {
    type Value = ();

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("JSON without duplicate object keys")
    }

    fn visit_bool<E>(self, _: bool) -> Result<(), E>
    where
        E: serde::de::Error,
    {
        Ok(())
    }

    fn visit_i64<E>(self, _: i64) -> Result<(), E>
    where
        E: serde::de::Error,
    {
        Ok(())
    }

    fn visit_u64<E>(self, _: u64) -> Result<(), E>
    where
        E: serde::de::Error,
    {
        Ok(())
    }

    fn visit_str<E>(self, _: &str) -> Result<(), E>
    where
        E: serde::de::Error,
    {
        Ok(())
    }

    fn visit_string<E>(self, _: String) -> Result<(), E>
    where
        E: serde::de::Error,
    {
        Ok(())
    }

    fn visit_none<E>(self) -> Result<(), E>
    where
        E: serde::de::Error,
    {
        Ok(())
    }

    fn visit_unit<E>(self) -> Result<(), E>
    where
        E: serde::de::Error,
    {
        Ok(())
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<(), A::Error>
    where
        A: SeqAccess<'de>,
    {
        while sequence.next_element_seed(RejectDuplicateKeys)?.is_some() {}
        Ok(())
    }

    fn visit_map<A>(self, mut map: A) -> Result<(), A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut keys = BTreeSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key) {
                return Err(serde::de::Error::custom("duplicate object key"));
            }
            map.next_value_seed(RejectDuplicateKeys)?;
        }
        Ok(())
    }
}
