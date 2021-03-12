//! Structures for reading the json metadata output of Il2CppInspector

use serde::Deserialize;

#[derive(Deserialize, Debug)]
pub struct MDFile {
    #[serde(rename = "addressMap")]
    pub addr_map: MDAddrMap,
}

#[derive(Deserialize, Debug)]
pub struct MDAddrMap {
    #[serde(rename = "methodDefinitions")]
    pub methods: Vec<MDMethod>,
    pub apis: Vec<MDFunction>,
    #[serde(rename = "methodInvokers")]
    pub method_invokers: Vec<MDFunction>,
}

#[derive(Deserialize, Debug)]
pub struct MDMethod {
    #[serde(rename = "virtualAddress")]
    pub virtual_addr: String,
    pub name: String,
    #[serde(rename = "signature")]
    pub sig: String,
    #[serde(rename = "dotNetSignature")]
    pub dot_net_sig: String,
}

#[derive(Deserialize, Debug)]
pub struct MDFunction {
    #[serde(rename = "virtualAddress")]
    pub virtual_addr: String,
    pub name: String,
    #[serde(rename = "signature")]
    pub sig: String,
}
