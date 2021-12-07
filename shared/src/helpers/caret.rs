pub struct Caret<'a, T> {
    pub slice: &'a [T],
}

impl<'a, T: Copy> Caret<'a, T> {
    pub fn next(&self) -> T {
        self.slice[0]
    }
}

#[macro_export]
macro_rules! take {
    ( 1, $caret:expr ) => {
        {
            let first = $caret.slice[0];
            $caret.slice = &$caret.slice[1..];
            first
        }
    };
    ( $count:expr, $caret:expr ) => {
        {
            let mut part = [0u8; $count];

            for it in 0..$count {
                part[it] = $caret.slice[it];
            }

            $caret.slice = &$caret.slice[$count..];
            part
        }
    };
}
