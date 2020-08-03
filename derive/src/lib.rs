extern crate proc_macro;

mod multihash;
mod utils;

use proc_macro::TokenStream;
use proc_macro_error::proc_macro_error;
use synstructure::{decl_derive, Structure};

decl_derive!([Multihash, attributes(mh)] => #[proc_macro_error] multihash);
fn multihash(s: Structure) -> TokenStream {
    multihash::multihash(s).into()
}
