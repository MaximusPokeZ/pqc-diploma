// Сборка статьи в формате Word по ГОСТ Р 7.0.7-2021 (структура статьи)
// и ГОСТ 7.32-2017 (оформление текста, как в ВКР). Запуск: node build_docx.js
const fs = require('fs');
const path = require('path');
const {
  Document, Packer, Paragraph, TextRun, ImageRun, Table, TableRow, TableCell, WidthType, AlignmentType,
  BorderStyle, Footer, PageNumber, LevelFormat, TabStopType, Tab, VerticalAlign, ShadingType,
  Math: OMath, MathRun, MathSubScript, MathSuperScript, MathSubSuperScript, MathSum, MathFraction,
} = require('docx');

const FONT = 'Times New Roman';
const SZ = 28;            // 14 pt
const LINE = 360;         // полуторный интервал
const INDENT = 709;       // абзацный отступ 1,25 см
const TEXT_W = 9354;      // 210 − 30 − 15 мм = 165 мм в twips
const FIG = path.join(__dirname, 'figures');

// ---------- разметка: **жирный**, *курсив*, _{нижний}, ^{верхний} ----------
function rich(str, base = {}) {
  const runs = [];
  const re = /\*\*(.+?)\*\*|\*(.+?)\*|_\{(.+?)\}|\^\{(.+?)\}/g;
  let last = 0, m;
  const push = (text, extra = {}) => { if (text) runs.push(new TextRun({ text, font: FONT, size: SZ, ...base, ...extra })); };
  while ((m = re.exec(str))) {
    push(str.slice(last, m.index));
    if (m[1] !== undefined) push(m[1], { bold: true });
    else if (m[2] !== undefined) push(m[2], { italics: true });
    else if (m[3] !== undefined) push(m[3], { subScript: true });
    else if (m[4] !== undefined) push(m[4], { superScript: true });
    last = re.lastIndex;
  }
  push(str.slice(last));
  return runs;
}

const body = [];
const P = (text, o = {}) => body.push(new Paragraph({
  alignment: o.align ?? AlignmentType.JUSTIFIED,
  indent: { firstLine: o.noIndent ? 0 : INDENT },
  spacing: { line: o.line ?? LINE, before: o.before ?? 0, after: o.after ?? 0 },
  keepNext: o.keepNext, children: rich(text, o.run || {}),
}));
const PN = (text, o = {}) => P(text, { ...o, noIndent: true });

const Struct = (title) => body.push(new Paragraph({
  alignment: AlignmentType.CENTER, spacing: { line: LINE, before: 240, after: 120 }, keepNext: true,
  children: [new TextRun({ text: title.toUpperCase(), font: FONT, size: SZ, bold: true })],
}));
const H1 = (title) => body.push(new Paragraph({
  indent: { firstLine: INDENT }, spacing: { line: LINE, before: 240, after: 120 }, keepNext: true, keepLines: true,
  children: [new TextRun({ text: title, font: FONT, size: SZ, bold: true })],
}));
const H2 = (title) => body.push(new Paragraph({
  indent: { firstLine: INDENT }, spacing: { line: LINE, before: 120, after: 60 }, keepNext: true, keepLines: true,
  children: [new TextRun({ text: title, font: FONT, size: SZ, bold: true })],
}));

// ---------- рисунки ----------
let figNo = 0;
function pngSize(file) { const b = fs.readFileSync(file); return [b.readUInt32BE(16), b.readUInt32BE(20)]; }
function Fig(name, caption) {
  const file = path.join(FIG, name);
  const [w, h] = pngSize(file);
  // PNG отрисованы с масштабом 3; ширина не больше полосы набора (16,5 см ≈ 620 px)
  const widthPx = Math.min(615, Math.round(w / 3 * (name === 'fig1.png' || name === 'fig2.png' ? 1 : 0.92)));
  figNo += 1;
  body.push(new Paragraph({
    alignment: AlignmentType.CENTER, spacing: { before: 120, after: 60 }, keepNext: true,
    children: [new ImageRun({ type: 'png', data: fs.readFileSync(file), transformation: { width: widthPx, height: Math.round(widthPx * h / w) } })],
  }));
  body.push(new Paragraph({
    alignment: AlignmentType.CENTER, spacing: { line: LINE, after: 120 },
    children: [new TextRun({ text: `Рисунок ${figNo} — ${caption}`, font: FONT, size: SZ })],
  }));
  return figNo;
}

// ---------- таблицы ----------
let tabNo = 0;
const border = { style: BorderStyle.SINGLE, size: 4, color: '000000' };
const borders = { top: border, bottom: border, left: border, right: border };
function cell(text, width, o = {}) {  // o.keep — не отрывать строку от следующей
  return new TableCell({
    borders, width: { size: width, type: WidthType.DXA }, verticalAlign: VerticalAlign.CENTER,
    margins: { top: 40, bottom: 40, left: 100, right: 100 },
    children: [new Paragraph({
      alignment: o.align ?? AlignmentType.LEFT, spacing: { line: 240 }, keepNext: o.keep,
      children: rich(text, { size: 24, bold: o.bold }),
    })],
  });
}
function Tbl(caption, header, rows, widths, aligns = []) {
  tabNo += 1;
  body.push(new Paragraph({
    spacing: { line: LINE, before: 120, after: 60 }, keepNext: true,
    children: [new TextRun({ text: `Таблица ${tabNo} — ${caption}`, font: FONT, size: SZ })],
  }));
  const mk = (cells, bold, keep = true) => new TableRow({
    tableHeader: bold, cantSplit: true,
    children: cells.map((c, i) => cell(c, widths[i], { bold, keep, align: bold ? AlignmentType.CENTER : aligns[i] })),
  });
  body.push(new Table({ width: { size: widths.reduce((a, b) => a + b, 0), type: WidthType.DXA }, columnWidths: widths,
    rows: [mk(header, true), ...rows.map((r, k) => mk(r, false, k < rows.length - 1))] }));
  body.push(new Paragraph({ spacing: { line: 240, after: 120 }, children: [] }));
  return tabNo;
}

// ---------- листинги ----------
let lstNo = 0;
function Listing(caption, lines) {
  lstNo += 1;
  body.push(new Paragraph({
    spacing: { line: LINE, before: 120, after: 60 }, keepNext: true,
    children: [new TextRun({ text: `Листинг ${lstNo} — ${caption}`, font: FONT, size: SZ })],
  }));
  body.push(new Table({
    width: { size: TEXT_W, type: WidthType.DXA }, columnWidths: [TEXT_W],
    rows: [new TableRow({ cantSplit: true, children: [new TableCell({
      borders, width: { size: TEXT_W, type: WidthType.DXA }, margins: { top: 80, bottom: 80, left: 140, right: 140 },
      children: lines.map(l => new Paragraph({ spacing: { line: 240 }, keepNext: true,
        children: [new TextRun({ text: l || ' ', font: 'Courier New', size: 20 })] })),
    })] })],
  }));
  body.push(new Paragraph({ spacing: { line: 240, after: 120 }, children: [] }));
}

// ---------- формулы (редактор формул Word) ----------
let eqNo = 0;
const r = (t) => new MathRun(t);
const sub = (b, s) => new MathSubScript({ children: [r(b)], subScript: [r(s)] });
const sup = (b, s) => new MathSuperScript({ children: typeof b === 'string' ? [r(b)] : b, superScript: typeof s === 'string' ? [r(s)] : s });
function Eq(children) {
  eqNo += 1;
  body.push(new Paragraph({
    tabStops: [{ type: TabStopType.CENTER, position: TEXT_W / 2 }, { type: TabStopType.RIGHT, position: TEXT_W }],
    spacing: { line: LINE, before: 60, after: 60 }, keepNext: false,
    children: [new TextRun({ children: [new Tab()], font: FONT, size: SZ }), new OMath({ children }),
      new TextRun({ children: [new Tab(), `(${eqNo})`], font: FONT, size: SZ })],
  }));
  return eqNo;
}

// ---------- списки «1)» ----------
const numbering = [];
let listNo = 0;
function List(items) {
  listNo += 1;
  const ref = `list${listNo}`;
  numbering.push({ reference: ref, levels: [{ level: 0, format: LevelFormat.DECIMAL, text: '%1)', alignment: AlignmentType.LEFT,
    style: { paragraph: { indent: { left: INDENT + 397, hanging: 397 } }, run: { font: FONT, size: SZ } } }] });
  items.forEach(it => body.push(new Paragraph({
    numbering: { reference: ref, level: 0 }, alignment: AlignmentType.JUSTIFIED, spacing: { line: LINE },
    children: rich(it),
  })));
}

const HL = { highlight: 'yellow' };

// =====================================================================
//                       МЕТАДАННЫЕ СТАТЬИ (ГОСТ Р 7.0.7-2021)
// =====================================================================
PN('Научная статья', { line: 276 });
PN('УДК 004.056.55', { line: 276, after: 200 });
body.push(new Paragraph({ alignment: AlignmentType.CENTER, spacing: { line: 276, after: 200 }, children: [new TextRun({
  text: 'Гибридная постквантовая криптографическая подсистема долговременного защищённого хранения цифровых активов на платформе Java 25',
  font: FONT, size: SZ, bold: true })] }));
PN('**Максим Владимирович Заславцев**', { align: AlignmentType.CENTER, line: 276 });
PN('Московский авиационный институт (национальный исследовательский университет), Москва, Россия', { align: AlignmentType.CENTER, line: 276 });
PN('mzaslavtsev@gmail.com', { align: AlignmentType.CENTER, line: 276, after: 200 });

P('**Аннотация.** Рассматривается задача защиты цифровых активов, которые должны сохранять конфиденциальность в течение 10–50 лет, от атаки «Harvest Now, Decrypt Later»: перехваченные сегодня шифротексты могут быть вскрыты алгоритмом Шора после появления криптографически значимого квантового компьютера. Предложена аппаратно-независимая подсистема хранения, в которой симметричный ключ данных выводится функцией HKDF из двух независимых общих секретов — классического механизма X25519 и постквантового механизма инкапсуляции ключа ML-KEM-768 (FIPS 203), а целостность и авторство обеспечиваются композитной подписью Ed25519 и ML-DSA-65 (FIPS 204). Для компенсации кратного роста постквантовых артефактов разработан конвейер «сжатие → шифрование» с адаптивным отказом от сжатия и предложен спектрально-энтропийный алгоритм сжатия FOURIER, основанный на быстром преобразовании Фурье и кодировании невязок в 8-битной модулярной арифметике. Подсистема реализована на штатных криптографических интерфейсах Java 25 в виде модуля Spring Boot Starter с поддержкой криптоагильности. Экспериментально показано, что алгоритм FOURIER сокращает объём телеметрических данных на 71 % против 21 % у ZSTD, предварительное сжатие ускоряет полный криптографический цикл на 29–34 %, а проверка подписи ML-DSA-65 выполняется в 8 раз быстрее, чем Ed25519.', { line: LINE });
P('**Ключевые слова:** постквантовая криптография, гибридная криптосистема, ML-KEM, ML-DSA, HKDF, Harvest Now Decrypt Later, сжатие перед шифрованием, быстрое преобразование Фурье, криптоагильность, Java 25');
P('**Благодарности:** автор выражает благодарность научному руководителю кандидату технических наук, доценту кафедры 806 МАИ Александру Михайловичу Романенкову за постановку задачи и ценные замечания.');
P('**Для цитирования:** Заславцев М. В. Гибридная постквантовая криптографическая подсистема долговременного защищённого хранения цифровых активов на платформе Java 25 // [Название журнала]. 2026. Т. [__], № [__]. С. [__]–[__].', { run: {}, after: 240 });

PN('Original article', { line: 276 });
body.push(new Paragraph({ alignment: AlignmentType.CENTER, spacing: { line: 276, before: 120, after: 200 }, children: [new TextRun({
  text: 'Hybrid post-quantum cryptographic subsystem for long-term secure storage of digital assets on the Java 25 platform',
  font: FONT, size: SZ, bold: true })] }));
PN('**Maksim V. Zaslavtsev**', { align: AlignmentType.CENTER, line: 276 });
PN('Moscow Aviation Institute (National Research University), Moscow, Russia', { align: AlignmentType.CENTER, line: 276 });
PN('mzaslavtsev@gmail.com', { align: AlignmentType.CENTER, line: 276, after: 200 });
P('**Abstract.** The paper addresses the protection of digital assets that must remain confidential for 10–50 years against the “Harvest Now, Decrypt Later” attack, in which ciphertexts intercepted today are decrypted with Shor’s algorithm once a cryptographically relevant quantum computer appears. A hardware-independent storage subsystem is proposed in which the data encryption key is derived by HKDF from two independent shared secrets produced by the classical X25519 mechanism and the post-quantum ML-KEM-768 key encapsulation mechanism (FIPS 203), while integrity and authenticity are provided by a composite Ed25519 and ML-DSA-65 signature (FIPS 204). To compensate for the multiple growth of post-quantum artefacts, a compress-then-encrypt pipeline with adaptive fallback is designed and a spectral-entropy compression algorithm FOURIER based on the fast Fourier transform and 8-bit modular residual coding is proposed. The subsystem is implemented on the standard Java 25 cryptographic APIs as a crypto-agile Spring Boot Starter. Experiments show that FOURIER reduces telemetry data by 71 % versus 21 % for ZSTD, pre-compression speeds up the full cryptographic cycle by 29–34 %, and ML-DSA-65 signature verification is 8 times faster than Ed25519.');
P('**Keywords:** post-quantum cryptography, hybrid cryptosystem, ML-KEM, ML-DSA, HKDF, Harvest Now Decrypt Later, compress-then-encrypt, fast Fourier transform, crypto-agility, Java 25');
P('**Acknowledgments:** the author thanks the scientific supervisor, Candidate of Technical Sciences, Associate Professor of Department 806 of MAI Aleksandr M. Romanenkov for setting the problem and valuable comments.');
P('**For citation:** Zaslavtsev M. V. Hybrid post-quantum cryptographic subsystem for long-term secure storage of digital assets on the Java 25 platform. [Journal title]. 2026;[__]([__]):[__]–[__]. (In Russ.).', { after: 120 });

// =====================================================================
//                                  ТЕКСТ
// =====================================================================
Struct('Введение');
P('Безопасность инфраструктуры открытых ключей, на которой основаны защищённые каналы связи, электронный документооборот и системы хранения, опирается на вычислительную сложность задач факторизации целых чисел и дискретного логарифмирования. Алгоритм Шора [1] решает обе задачи за полиномиальное время на квантовом вычислителе, поэтому появление криптографически значимого квантового компьютера (CRQC) переводит алгоритмы RSA, DH, ECDH и ECDSA в класс практически взламываемых. Симметричные алгоритмы с ключом 256 бит, в том числе AES-256, сохраняют стойкость и в квантовую эпоху.');
P('Для систем хранения данных в состоянии покоя (Data-at-Rest) критична не дата появления CRQC, а модель угроз «Harvest Now, Decrypt Later» (HNDL): злоумышленник уже сегодня накапливает перехваченные контейнеры — архивы, резервные копии, конструкторскую документацию — чтобы расшифровать их после появления квантового вычислителя. Экспертные оценки вероятности появления CRQC в горизонте 10–15 лет [2] сопоставимы с требуемыми сроками конфиденциальности, а в авиационно-космической отрасли жизненный цикл изделия и его документации составляет 20–50 лет. Следовательно, данные, зашифрованные классическими асимметричными схемами сегодня, следует считать уже скомпрометированными в перспективе.');
P('В августе 2024 г. NIST утвердил стандарты постквантовой криптографии ML-KEM (FIPS 203) [3] и ML-DSA (FIPS 204) [4], а начиная с версии 24 платформа Java содержит их штатные реализации (JEP 496, JEP 497) [5, 6], что позволяет применять их в корпоративных приложениях без сторонних нативных библиотек.');
P('Целью работы является создание аппаратно-независимой подсистемы долговременного защищённого хранения цифровых активов, устойчивой к квантовым атакам и пригодной к внедрению в существующие микросервисные системы. Для достижения цели решены следующие задачи:');
List([
  'синтез гибридной криптографической схемы с безопасным смешиванием классического и постквантового секретов;',
  'реализация гибридных механизмов инкапсуляции ключа и электронной подписи на основе стандартов FIPS 203 и FIPS 204;',
  'проектирование конвейера «сжатие → шифрование», компенсирующего рост размера постквантовых артефактов, и разработка алгоритма сжатия сигнальных данных FOURIER;',
  'реализация программного модуля Spring Boot Starter с поддержкой криптоагильности;',
  'экспериментальная оценка накладных расходов и производительности подсистемы.',
]);

H1('1 Угроза HNDL и обоснование гибридного подхода');
H2('1.1 Постквантовые стандарты NIST');
P('Механизм ML-KEM предназначен для замены протоколов согласования ключей на основе Диффи — Хеллмана и обеспечивает двум сторонам выработку общего симметричного секрета по незащищённому каналу [3]. Его стойкость основана на задаче обучения с ошибками в модульных решётках (Module-LWE) [7, 8]. Важной инженерной особенностью является механизм неявного отказа (implicit rejection): при модифицированном шифротексте алгоритм не формирует исключение, а возвращает псевдослучайный ключ, что исключает атаки по времени и через оракул расшифрования. Параметры ML-KEM приведены в таблице 1.');
Tbl('Наборы параметров ML-KEM (FIPS 203)',
  ['Набор параметров', 'Уровень NIST', 'Эквивалент', 'Открытый ключ, байт', 'Шифротекст, байт'],
  [['ML-KEM-512', '1', 'AES-128', '800', '768'], ['ML-KEM-768', '3', 'AES-192', '1184', '1088'], ['ML-KEM-1024', '5', 'AES-256', '1568', '1568']],
  [2154, 1650, 1650, 1950, 1950], [AlignmentType.LEFT, AlignmentType.CENTER, AlignmentType.CENTER, AlignmentType.CENTER, AlignmentType.CENTER]);
P('Алгоритм ML-DSA построен по схеме Fiat — Shamir with Aborts и, в отличие от ECDSA, допускает детерминированный режим формирования подписи, при котором качество системного генератора случайных чисел не влияет на безопасность закрытого ключа [4]. Для рекомендуемого набора ML-DSA-65 (уровень 3) открытый ключ занимает 1952 байта, а подпись — 3309 байт, что на один-два порядка превышает размеры классических аналогов и определяет основную инженерную проблему внедрения.');

H2('1.2 Модель угроз');
P('Несмотря на стандартизацию, криптоанализ решёточных схем значительно моложе, чем у RSA и эллиптических кривых. Показательна судьба алгоритма SIKE: дойдя до четвёртого раунда конкурса NIST, он был полностью взломан на однопроцессорном компьютере за время порядка часа [9]. Поэтому национальные регуляторы — ANSSI (Франция) и BSI (Германия) — рекомендуют на переходном этапе применять постквантовые алгоритмы только в гибридном сочетании с классическими [10, 11]. Сравнение архитектур по трём классам противников приведено в таблице 2.');
Tbl('Устойчивость архитектур к различным противникам',
  ['Архитектура', 'Классический противник', 'Противник с CRQC', 'Взлом математики решёток'],
  [['Классическая (RSA, ECC)', 'стойкая', 'уязвима', 'не применимо'], ['Только PQC (ML-KEM)', 'стойкая', 'стойкая', 'уязвима'], ['Гибридная (предложенная)', 'стойкая', 'стойкая', 'стойкая']],
  [2754, 2200, 2200, 2200], [AlignmentType.LEFT, AlignmentType.CENTER, AlignmentType.CENTER, AlignmentType.CENTER]);
P('Гибридная схема сохраняет стойкость, пока не скомпрометированы одновременно оба составляющих примитива. Формально стойкость гибридной схемы оценивается снизу стойкостью сильнейшего компонента:');
Eq([sub('S', 'hyb'), r(' ≥ max('), sub('S', 'cl'), r(', '), sub('S', 'pq'), r(')')]);
PN('где *S*_{cl} и *S*_{pq} — стойкость классического и постквантового компонентов соответственно. Оценка (1) справедлива лишь при корректном комбинировании секретов, рассмотренном в разделе 2.');

H1('2 Архитектура подсистемы хранения');
H2('2.1 Гибридная инкапсуляция ключа');
P('Общая схема подсистемы показана на рисунке 1. Для шифрования актива используется конвертная схема: тело данных шифруется симметричным ключом данных (DEK) алгоритмом AES-256-GCM, а сам ключ выводится из результатов двух независимых механизмов инкапсуляции — X25519 и ML-KEM-768 — с открытыми ключами получателя.');
Fig('fig1.png', 'Архитектура гибридного конвейера защищённого хранения');
P('Наивное объединение секретов, например вычисление хеш-функции от их конкатенации, уязвимо к атакам на неоднозначность разбора и не обеспечивает доказуемой стойкости [12]. В разработанном классе *HybridCombiner* секреты объединяются с префиксами длины:');
Eq([r('IKM = '), sub('I', '32'), r('(|'), sub('K', 'cl'), r('|) ‖ '), sub('K', 'cl'), r(' ‖ '), sub('I', '32'), r('(|'), sub('K', 'pq'), r('|) ‖ '), sub('K', 'pq')]);
PN('где *K*_{cl}, *K*_{pq} — общие секреты X25519 и ML-KEM; *I*_{32}(·) — 4-байтовое представление длины в порядке big-endian; ‖ — конкатенация. Затем применяется функция HKDF на основе HMAC-SHA256 [13]:');
Eq([r('PRK = HMAC‑SHA256(salt, IKM)')]);
Eq([r('K = HKDF‑Expand(PRK, info, 32)')]);
PN('где в качестве *salt* и *info* используется метка домена «PQC-HYBRID-KEM-v1», обеспечивающая разделение контекстов, а *K* — 256-битный ключ данных. Промежуточные значения IKM и PRK затираются нулями сразу после использования.');

H2('2.2 Гибридная электронная подпись');
P('Для контроля целостности и авторства контейнера используется композитная подпись, объединяющая классическую и постквантовую подписи одного сообщения *m*:');
Eq([r('σ = '), sub('I', '32'), r('(|'), sub('σ', 'cl'), r('|) ‖ '), sub('σ', 'cl'), r(' ‖ '), sub('I', '32'), r('(|'), sub('σ', 'pq'), r('|) ‖ '), sub('σ', 'pq')]);
Eq([r('Verify(m, σ) = '), sub('Verify', 'cl'), r('(m, '), sub('σ', 'cl'), r(') ∧ '), sub('Verify', 'pq'), r('(m, '), sub('σ', 'pq'), r(')')]);
PN('Подпись принимается только при успешной проверке обеих частей. Такая конструкция обеспечивает неотказуемость в будущем: после компрометации классических алгоритмов квантовым компьютером постквантовая часть продолжает подтверждать подлинность документа. По умолчанию используется пара Ed25519 и ML-DSA-65; поддерживаются также ECDSA P-256 и RSA-2048.');

H2('2.3 Формат контейнера');
P('Результат шифрования сериализуется в самоописываемый двоичный контейнер *EncryptedMessage* (рисунок 2). Заголовок содержит версию формата, идентификаторы алгоритмов инкапсуляции и сжатия и длину блока инкапсуляций, что позволяет расшифровать контейнер спустя годы, даже если конфигурация системы изменилась. Тело AES-256-GCM аутентифицируется 16-байтовым тегом, поэтому любая модификация контейнера обнаруживается при расшифровании.');
Fig('fig2.png', 'Формат контейнера EncryptedMessage');
P('Ключевой материал хранится в классе *SecureBytes* (интерфейс AutoCloseable): при выходе из блока try-with-resources массивы с ключами затираются, что снижает риск их утечки через дампы памяти JVM.');

H2('2.4 Криптоагильность и интеграция в Spring Boot');
P('Под криптоагильностью понимается возможность замены криптографических алгоритмов и параметров без изменения бизнес-логики. Разработанный модуль *pqc-hybrid-spring-boot-starter* средствами автоконфигурации Spring Boot создаёт компоненты *HybridEncryptor* и *HybridSigner* по свойствам конфигурации (листинг 1). Поддерживаются три режима — HYBRID (по умолчанию), PQC_ONLY и CLASSICAL_ONLY, наборы параметров ML-KEM-512/768/1024 и ML-DSA-44/65/87, а также алгоритмы сжатия GZIP, ZSTD, LZ4 и FOURIER.');
Listing('Конфигурация модуля в файле application.yml', [
  'pqc:', '  encryption:', '    mode: HYBRID', '    pqc-algorithm: ML_KEM_768', '    classical-algorithm: X25519',
  '    compression:', '      enabled: true', '      algorithm: ZSTD', '  signature:', '    mode: HYBRID',
  '    pqc-algorithm: ML_DSA_65', '    classical-algorithm: ED25519']);
P('Модуль использует только штатные интерфейсы Java Cryptography Architecture платформы Java 25, поэтому не требует нативных библиотек на C/C++ и сохраняет переносимость. Переход на будущие стандарты, в том числе отечественные постквантовые алгоритмы, сводится к добавлению провайдера и изменению конфигурации.');

H1('3 Конвейер «сжатие → шифрование» и алгоритм FOURIER');
H2('3.1 Обоснование порядка операций');
P('Платой за квантовую устойчивость является кратный рост служебных данных: гибридная инкапсуляция увеличивает накладные расходы контейнера с 79 до 1175 байт, а гибридная подпись — с 64 до 3381 байт. Для систем хранения, оперирующих миллионами объектов, это приводит к заметному росту требований к хранилищу и каналам репликации.');
P('Шифротекст AES-GCM статистически неотличим от случайной последовательности и обладает максимальной энтропией, поэтому сжатие после шифрования бесполезно и лишь увеличивает объём за счёт служебных заголовков архиватора. В связи с этим класс *HybridEncryptor* реализует паттерн Compress-then-Encrypt: сжатие применяется к открытому тексту, пока он сохраняет семантическую избыточность, а идентификатор алгоритма сжатия фиксируется в заголовке контейнера. Поскольку подсистема предназначена для хранения, а не для интерактивного обмена, атаки, использующие зависимость длины сжатого текста от секретных данных, неприменимы к рассматриваемой модели угроз.');
H2('3.2 Адаптивный отказ от сжатия');
P('Если входные данные уже сжаты или зашифрованы, попытка их сжатия увеличивает объём. Поэтому после сжатия выполняется проверка: если результат не меньше исходных данных, сжатие отменяется, а в заголовок записывается маркер NONE. Эксперимент на 5000 байтах псевдослучайных данных подтвердил, что размер контейнера остаётся постоянным (6175 байт) независимо от выбранного алгоритма.');
H2('3.3 Спектрально-энтропийный алгоритм FOURIER');
P('Словарные алгоритмы семейства LZ77, лежащие в основе GZIP, ZSTD и LZ4, эффективны на данных с повторяющимися подстроками, но плохо работают на плавных градиентах и периодических сигналах — телеметрии, растровых снимках, аудиоданных, где точные побайтовые повторения практически отсутствуют. Для таких данных предложен алгоритм FOURIER, сочетающий спектральную аппроксимацию и энтропийное кодирование.');
P('Входной массив разбивается на блоки длиной *N* = 1024 байта. Каждый блок рассматривается как дискретный сигнал *x*_{n} и переводится в частотную область быстрым преобразованием Фурье по алгоритму Кули — Тьюки [14]:');
Eq([sub('X', 'k'), r(' = '), new MathSum({ children: [sub('x', 'n'), r(' '), sup('e', [r('−2πikn/N')])], subScript: [r('n=0')], superScript: [r('N−1')] }), r(',  k = 0, …, N−1')]);
P('Из спектра сохраняются только *L* = 8 низкочастотных гармоник, остальные коэффициенты обнуляются. Обратное преобразование отфильтрованного спектра даёт сглаженное предсказание сигнала:');
Eq([sub('x̂', 'n'), r(' = round(Re '), sup('F', '−1'), r('['), sub('X̃', 'k'), r(']), '), sub('X̃', 'k'), r(' = '), sub('X', 'k'), r(' при k < L, иначе 0')]);
P('Поскольку предсказание близко к исходным данным, невязки принимают преимущественно малые значения, сосредоточенные около нуля, то есть энтропия блока резко снижается. Невязки вычисляются в 8-битной модулярной арифметике:');
Eq([sub('r', 'n'), r(' = ('), sub('x', 'n'), r(' − '), sub('x̂', 'n'), r(') mod 256')]);
P('В выходной буфер записываются длина исходных данных, коэффициенты сохранённых гармоник (по два 32-битных числа с плавающей точкой на гармонику) и массив невязок, после чего буфер кодируется алгоритмом ZSTD. При декомпрессии предсказание вычисляется по сохранённым гармоникам тем же детерминированным способом, и исходные байты восстанавливаются строго без потерь:');
Eq([sub('x', 'n'), r(' = ('), sub('x̂', 'n'), r(' + '), sub('r', 'n'), r(') mod 256')]);
P('В реализации на Java операция по модулю 256 выполняется приведением разности к типу byte: переполнение разрядной сетки естественно «закольцовывается», что исключает ветвления в горячем цикле и экономит такты процессора.');
H1('4 Экспериментальная оценка');
H2('4.1 Методика эксперимента');
P('Для профилирования разработано демонстрационное приложение на Spring Boot с экспортом метрик в Prometheus и Grafana. Каждое измерение выполнялось после трёх итераций прогрева JIT-компилятора и усреднялось по 20 итерациям в одном потоке процессора. Исходный код подсистемы и стенда опубликован в открытом репозитории [15].');
H2('4.2 Накладные расходы и масштабирование уровня безопасности');
P('Классический механизм X25519 добавляет к размеру сообщения 79 байт (инкапсулированный ключ, nonce и тег AES-GCM), гибридный механизм X25519 + ML-KEM-768 — 1175 байт, то есть служебная часть возрастает примерно в 15 раз. Влияние выбранного уровня безопасности на габариты гибридного KEM-сообщения показано в таблице 3.');
Tbl('Влияние уровня безопасности на габариты гибридного KEM-сообщения',
  ['Конфигурация', 'Открытый ключ, байт', 'Инкапсуляции, байт', 'Эквивалентная стойкость'],
  [['HYBRID (ML-KEM-512)', '32 + 800 = 832', '32 + 768 = 800', 'AES-128'], ['HYBRID (ML-KEM-768)', '32 + 1184 = 1216', '32 + 1088 = 1120', 'AES-192 (рекомендуется)'], ['HYBRID (ML-KEM-1024)', '32 + 1568 = 1600', '32 + 1568 = 1600', 'AES-256']],
  [2654, 2200, 2200, 2300], [AlignmentType.LEFT, AlignmentType.CENTER, AlignmentType.CENTER, AlignmentType.CENTER]);
P('Набор ML-KEM-768 выбран по умолчанию как компромисс: он обеспечивает стойкость, эквивалентную AES-192, и увеличивает блок инкапсуляций лишь на 320 байт по сравнению с ML-KEM-512.');
H2('4.3 Эффективность сжатия');
P('На первом этапе алгоритмы сжатия сравнивались на текстовом документе объёмом 22 500 байт с высокой семантической избыточностью (рисунок 3). Наилучший результат показал ZSTD (1239 байт, сокращение на 94,8 %), алгоритмы GZIP и LZ4 оказались близки к нему. Алгоритм FOURIER сократил контейнер на 86,2 %, что ожидаемо уступает словарным методам на естественном языке.');
Fig('fig3.png', 'Размер итогового контейнера для текстовых данных объёмом 22 500 байт');
P('На втором этапе использовался массив сырых телеметрических данных пространственного сканирования объёмом 50 000 байт — несжатый растровый градиент с наложенным аппаратным шумом, характерный для бортовых регистраторов и систем дистанционного зондирования (рисунок 4). Словарные алгоритмы не нашли повторяющихся подстрок: LZ4 сократил объём лишь на 7 %, ZSTD — на 21 %. Алгоритм FOURIER сжал массив до 14 350 байт (на 71 %), что в 3,5 раза снижает объём данных, поступающих на шифрование. Поэтому для корпоративных документов алгоритмом по умолчанию остаётся ZSTD, а FOURIER включается конфигурацией для архивов сигнальных и растровых данных.');
Fig('fig4.png', 'Сравнение степени сжатия телеметрических данных объёмом 50 000 байт');
H2('4.4 Временные характеристики и пропускная способность');
P('Измерение длительности полного цикла «шифрование + расшифрование» выявило контринтуитивный эффект: включение сжатия не замедляет, а ускоряет работу подсистемы (рисунок 5). Для LZ4 время цикла сократилось с 0,96 до 0,68 мс (на 29 %), для ZSTD и FOURIER — на 30 и 34 % соответственно. Это объясняется тем, что затраты процессорного времени на сжатие ниже затрат на AEAD-преобразование и копирование исходного объёма памяти.');
Fig('fig5.png', 'Время полного цикла шифрования и расшифрования без сжатия и со сжатием');
P('Пропускная способность измерялась на непрерывном потоке документов объёмом 10 КБ (рисунок 6). Переход на гибридную схему ожидаемо снижает её с 15 200 операций в секунду для X25519 до 4100 операций в секунду, однако включение сжатия LZ4 повышает её до 5300 операций в секунду за счёт уменьшения объёма, обрабатываемого шифратором. Производительность свыше 5000 операций в секунду на одном ядре достаточна для промышленного применения.');
Fig('fig6.png', 'Пропускная способность подсистемы конвертного шифрования');
H2('4.5 Электронная подпись');
P('Классическая подпись Ed25519 занимает 64 байта, подпись ML-DSA-65 — 3309 байт, а гибридная подпись с двумя 4-байтовыми префиксами длины — 3381 байт (64 + 3309 + 8). Генерация гибридной пары ключей занимает в среднем 1,8 мс против 0,4 мс для Ed25519, поэтому ключи подписи следует создавать однократно при старте сервиса или по расписанию ротации, а не при каждой операции.');
P('Средние задержки формирования и проверки подписи для девяти конфигураций приведены на рисунке 7. Несмотря на размер ключей, вычисления ML-DSA выполняются быстро: формирование подписи ML-DSA-65 занимает 0,18 мс, что в 5,5 раза быстрее RSA-2048, а проверка — 0,055 мс, что в 8 раз быстрее Ed25519. Задержка гибридной подписи приблизительно равна сумме задержек составляющих, что подтверждает отсутствие узких мест в реализации композитного провайдера.');
Fig('fig7.png', 'Средние задержки формирования (а) и проверки (б) электронной подписи');
H2('4.6 Обсуждение и ограничения');
P('Основная цена перехода на гибридную постквантовую криптографию — рост размера артефактов, а не вычислительная сложность, и этот рост эффективно компенсируется предварительным сжатием. Ограничения работы — измерения на одной аппаратной платформе в однопоточном режиме и узкая область эффективности алгоритма FOURIER; перспективным направлением является адаптивный выбор алгоритма сжатия по статистике входных данных.');

Struct('Заключение');
P('В работе предложена и реализована гибридная постквантовая подсистема долговременного защищённого хранения цифровых активов. Получены следующие основные результаты:');
List([
  'разработана схема гибридной инкапсуляции ключа X25519 + ML-KEM-768 с объединением секретов функцией HKDF и префиксами длины, сохраняющая стойкость до одновременной компрометации обоих примитивов;',
  'реализована композитная электронная подпись Ed25519 + ML-DSA-65, обеспечивающая долговременную неотказуемость;',
  'предложен конвейер «сжатие → шифрование» с адаптивным отказом от сжатия и спектрально-энтропийный алгоритм FOURIER, сокращающий объём телеметрических данных на 71 % против 21 % у ZSTD;',
  'экспериментально показано, что предварительное сжатие ускоряет полный криптографический цикл на 29–34 % и повышает пропускную способность гибридного режима с 4100 до 5300 операций в секунду;',
  'подсистема оформлена в виде криптоагильного модуля Spring Boot Starter на штатных интерфейсах Java 25, готового к внедрению в корпоративные системы.',
]);
P('Практическая значимость работы состоит в возможности уже сейчас защитить архивы с длительным сроком конфиденциальности от угрозы HNDL — в первую очередь в авиационно-космической и оборонной отраслях, где горизонт эксплуатации изделий превышает прогнозируемые сроки появления квантовых компьютеров.');

Struct('Список источников');
const refs = [
  'Shor P. W. Polynomial-Time Algorithms for Prime Factorization and Discrete Logarithms on a Quantum Computer // SIAM Journal on Computing. 1997. Vol. 26, no. 5. P. 1484–1509.',
  'Mosca M., Piani M. Quantum Threat Timeline Report 2024. Toronto : Global Risk Institute, 2024. 98 p.',
  'FIPS 203. Module-Lattice-Based Key-Encapsulation Mechanism Standard. Gaithersburg : NIST, 2024. 47 p. DOI: 10.6028/NIST.FIPS.203.',
  'FIPS 204. Module-Lattice-Based Digital Signature Standard. Gaithersburg : NIST, 2024. 55 p. DOI: 10.6028/NIST.FIPS.204.',
  'JEP 496: Quantum-Resistant Module-Lattice-Based Key Encapsulation Mechanism. URL: https://openjdk.org/jeps/496 (дата обращения: 15.10.2026).',
  'JEP 497: Quantum-Resistant Module-Lattice-Based Digital Signature Algorithm. URL: https://openjdk.org/jeps/497 (дата обращения: 15.10.2026).',
  'Bernstein D. J., Buchmann J., Dahmen E. Post-Quantum Cryptography. Berlin : Springer, 2009. 245 p.',
  'Hoffstein J., Pipher J., Silverman J. H. An Introduction to Mathematical Cryptography. 2nd ed. New York : Springer, 2014. 538 p.',
  'Castryck W., Decru T. An Efficient Key Recovery Attack on SIDH // Advances in Cryptology – EUROCRYPT 2023. Cham : Springer, 2023. P. 423–447.',
  'ANSSI views on the Post-Quantum Cryptography transition (2023 follow up). Paris : ANSSI, 2023. URL: https://cyber.gouv.fr/en/publications/follow-position-paper-post-quantum-cryptography (дата обращения: 15.10.2026).',
  'Quantum-safe cryptography – fundamentals, current developments and recommendations. Bonn : BSI, 2022. 112 p.',
  'Bindel N., Brendel J., Fischlin M., Goncalves B., Stebila D. Hybrid Key Encapsulation Mechanisms and Authenticated Key Exchange // Post-Quantum Cryptography. PQCrypto 2019. Cham : Springer, 2019. P. 206–226.',
  'Krawczyk H., Eronen P. HMAC-based Extract-and-Expand Key Derivation Function (HKDF) : RFC 5869. IETF, 2010. URL: https://www.rfc-editor.org/rfc/rfc5869 (дата обращения: 15.10.2026).',
  'Cooley J. W., Tukey J. W. An Algorithm for the Machine Calculation of Complex Fourier Series // Mathematics of Computation. 1965. Vol. 19, no. 90. P. 297–301.',
  'Заславцев М. В. pqc-diploma : гибридная постквантовая криптография для Java 25 и Spring Boot : исходный код. URL: https://github.com/MaximusPokeZ/pqc-diploma (дата обращения: 15.10.2026).',
];
numbering.push({ reference: 'refs', levels: [{ level: 0, format: LevelFormat.DECIMAL, text: '%1.', alignment: AlignmentType.LEFT,
  style: { paragraph: { indent: { left: INDENT + 397, hanging: 397 } }, run: { font: FONT, size: SZ } } }] });
refs.forEach(t => body.push(new Paragraph({ numbering: { reference: 'refs', level: 0 }, alignment: AlignmentType.JUSTIFIED,
  spacing: { line: LINE }, children: rich(t) })));

// =====================================================================
const doc = new Document({
  creator: 'М. В. Заславцев', title: 'Гибридная постквантовая криптографическая подсистема', description: 'Научная статья',
  styles: { default: { document: { run: { font: FONT, size: SZ } } } },
  numbering: { config: numbering },
  sections: [{
    properties: { page: { size: { width: 11906, height: 16838 }, margin: { top: 1134, bottom: 1134, left: 1701, right: 850, footer: 567 } } },
    footers: { default: new Footer({ children: [new Paragraph({ alignment: AlignmentType.CENTER,
      children: [new TextRun({ children: [PageNumber.CURRENT], font: FONT, size: SZ })] })] }) },
    children: body,
  }],
});
Packer.toBuffer(doc).then(buf => {
  const out = path.join(__dirname, 'article.docx');
  fs.writeFileSync(out, buf);
  console.log('written', out);
});
