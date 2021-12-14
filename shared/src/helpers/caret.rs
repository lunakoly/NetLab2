use crate::{Result, ErrorKind};

pub struct Caret<'a, T> {
    pub slice: &'a [T],
}

impl<'a, T: Copy> Caret<'a, T> {
    pub fn next(&self) -> T {
        self.slice[0]
    }

    pub fn has_next(&self) -> bool {
        self.slice.len() > 0
    }

    pub fn take(&mut self, count: usize) -> Result<Vec<T>> {
        if self.slice.len() < count {
            return ErrorKind::UnsupportedFormat {
                message: "Not enough bytes to take".to_owned(),
            }.into()
        }

        let result = self.slice[..count].to_vec();
        self.slice = &self.slice[count..];
    
        Ok(result)
    }
}

// impl<'a> Caret<'a, u8> {
//     pub fn fill(&mut self, buffer: &mut [u8]) -> Result<()> {
//         if self.slice.len() < buffer.len() {
//             return ErrorKind::UnsupportedFormat {
//                 message: "Not enough bytes to fill the buffer".to_owned(),
//             }.into()
//         }

//         for it in 0..buffer.len() {
//             buffer[it] = self.slice[it];
//         }

//         self.slice = &self.slice[buffer.len()..];
//         Ok(())
//     }
// }

#[macro_export]
macro_rules! take {
    ( 1, $caret:expr ) => {
        {
            if $caret.slice.len() < 1 {
                return ErrorKind::UnsupportedFormat {
                    message: "Not enough bytes".to_owned(),
                }.into()
            }
            
            let first = $caret.slice[0];
            $caret.slice = &$caret.slice[1..];
            first
        }
    };
    ( $count:expr, $caret:expr ) => {
        {
            if $caret.slice.len() < $count {
                return ErrorKind::UnsupportedFormat {
                    message: "Not enough bytes".to_owned(),
                }.into()
            }

            let mut part = [0u8; $count];

            for it in 0..$count {
                part[it] = $caret.slice[it];
            }

            $caret.slice = &$caret.slice[$count..];
            part
        }
    };
}
