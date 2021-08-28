// SPDX-License-Identifier: MIT OR Apache-2.0
#![allow(non_upper_case_globals)]

pub struct Language {
	pub name: &'static str,
	words: [&'static str; 2048],
	num_for_word: fn(&str) -> Option<u16>,
}
impl Language {
	pub const fn word_for_num(&self, wordnum: u16) -> Option<&'static str> {
		let wn = wordnum as usize;
		if wn < self.words.len() {
			Some(self.words[wn])
		} else {
			None
		}
	}
	pub fn num_for_word(&self, word: &str) -> Option<u16> {
		(self.num_for_word)(word)
	}
}

pub fn language(lang: &str) -> Option<&'static Language> {
	LANGUAGES.iter().map(|l|*l).find(|l|l.name == lang)
}

include!(concat!(env!("OUT_DIR"), "/languages.incl.rs"));