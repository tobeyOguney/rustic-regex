pub enum Ast {
    Expression(Expression),
    ExpressionProcess(ExpressionProcess),
    ExpressionReference(&str),
    ExpressionReferenceFactory(&str, Expression),
}

pub enum Expression {
    Safe(SafeExpression),
    Unsafe(UnsafeExpression), // TODO
}

pub enum ExpressionProcess {
    Safe(SafeExpressionProcess),
    Unsafe(UnsafeExpressionProcess), // TODO
}

pub enum SafeExpression {
    CharacterDescriptor(SafeExpressionCharacterDescriptor),
    PositionDescriptor(SafeExpressionPositionDescriptor),
}

pub enum UnsafeExpression {
    CharacterDescriptor(UnsafeExpressionCharacterDescriptor),
    PositionDescriptor(UnsafeExpressionPositionDescriptor),
}

pub enum SafeExpressionProcess {
    Alternation(Vec<SafeExpression>),
    Concatenation(Vec<SafeExpression>),
    Modification(SafeExpressionModificationMode, SafeExpression),
    Repetition(SafeExpressionRepetitionMode, SafeExpressionRepetitionProcess),
    Capture(SafeExpressionCaptureProcess),
    Interaction(SafeExpressionInteractionMode, SafeExpression, SafeExpression),
}

pub enum UnsafeExpressionProcess {
    Alternation(Vec<UnsafeExpression>),
    NonBacktrackingAlternation(Vec<UnsafeExpression>),
    Concatenation(Vec<UnsafeExpression>),
    Repetition(UnsafeExpressionRepetitionMode, UnsafeExpressionRepetitionProcess),
    Capture(UnsafeExpressionCaptureProcess),
    BackReference(usize),
    StartMatchFromHere,
    BackReferenceExistsCondition(usize),
    ConditionalExpression(Box<UnsafeExpressionProcess>, UnsafeExpression, UnsafeExpression),
}

pub enum SafeExpressionCharacterDescriptor {
    Literal(&str),
    CharacterRange(Literal, Literal),
    AsciiCharacterGroup(SafeExpressionAsciiCharacterGroup),
    UnicodeCharacterGroup(SafeExpressionUnicodeCharacterGroup),
    Composite(Vec<SafeExpressionCharacterDescriptor>),
}

pub enum UnsafeExpressionCharacterDescriptor {
    CaseSensitiveLiteral(&str),
    CaseInsensitiveLiteral(&str),
}

pub enum SafeExpressionPositionDescriptor {
    StartOfLine,
    EndOfLine,
    StartOfText,
    EndOfText,
    StartOrEndOfWord,
    NotStartNorEndOfWord,
    StartOfWord,
    EndOfWord,
    MidwayFromStartOfWord,
    MidwayFromEndOfWord,
}

pub enum UnsafeExpressionPositionDescriptor {
    AheadOf(Expression),
    Behind(Expression),
    NotAheadOf(Expression),
    NotBehind(Expression),
    PreviousMatchEnd,
}

pub enum SafeExpressionAsciiCharacterGroup {
    Alphanumeric,
    NotAlphanumeric,
    Alphabetic,
    NotAlphabetic,
    Any,
    None,
    Blank,
    NotBlank,
    Control,
    NotControl,
    Digit,
    NotDigit,
    Graphical,
    NotGraphical,
    Lowercase,
    Uppercase,
    Printable,
    NotPrintable,
    Punctuation,
    NotPunctuation,
    Whitespace,
    NotWhitespace,
    Word,
    NotWord,
    Hexadecimal,
    NotHexadecimal,
}

pub enum SafeExpressionUnicodeCharacterGroup {
    Letter,
    NotLetter,
    HasPropertyWithValue(&str, &str),
    DoesNotHavePropertyWithValue(&str, &str),
}

pub enum SafeExpressionRepetitionProcess {
    ZeroOrMore(SafeExpression),
    OneOrMore(SafeExpression),
    ZeroOrOne(SafeExpression),
    Exactly(usize, SafeExpression),
    AtLeast(usize, SafeExpression),
    AtMost(usize, SafeExpression),
    Range(usize, usize, SafeExpression),
}

pub enum SafeExpressionCaptureProcess {
    CaptureByIndex(usize, SafeExpression),
    CaptureByName(&str, SafeExpression),
}

pub enum SafeExpressionRepetitionMode {
    Greedy,
    Lazy,
}

pub enum SafeExpressionModificationMode {
    Negate,
    MakeCaseInsensitive,
    EnableMultiLineMatch,
    MakeNewlineMatchAsCharacter,
    SwapGreedyAndLazyRepetitionModes,
    EnableUnicodeCharacters,
    EnableCarriageReturnLineFeed,
    IgnoreWhitespace,
}

pub enum SafeExpressionInteractionMode {
    Intersection,
    Difference,
    SymmetricDifference,
}
