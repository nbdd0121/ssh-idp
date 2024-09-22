/// Helper type to display a value using `Display` instead `Debug` when formatting through `Debug`.
pub struct FmtAsDisplay<T>(pub T);

impl<T: std::fmt::Display> std::fmt::Debug for FmtAsDisplay<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}
