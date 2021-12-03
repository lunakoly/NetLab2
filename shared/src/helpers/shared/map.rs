use std::collections::{HashMap};
use std::borrow::{Borrow};
use std::hash::{Hash};

use crate::{Result};
use crate::shared::{Shared};

pub type SharedMap<K, V> = Shared<HashMap<K, V>>;

impl<K, V> SharedMap<K, V>
where
    K: Eq + Hash,
{
    pub fn contains_key<Q>(&self, key: &Q) -> Result<bool>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        Ok(self.inner.read()?.contains_key(key))
    }

    pub fn get_clone<Q>(&self, key: &Q) -> Result<Option<V>>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
        V: Clone
    {
        match self.inner.write()?.get(key) {
            Some(it) => Ok(Some(it.clone())),
            None => Ok(None)
        }
    }

    pub fn remove<Q: ?Sized>(&self, key: &Q) -> Result<Option<V>>
    where
        K: Borrow<Q>,
        Q: Hash + Eq
    {
        Ok(self.inner.write()?.remove(key))
    }

    pub fn insert(&self, key: K, value: V) -> Result<Option<V>> {
        Ok(self.inner.write()?.insert(key, value))
    }
}
