// pshist - сборщик истории PowerShell из всех доступных источников (Windows).
// Источники:
//   1. ConsoleHost_history.txt (PSReadLine) всех профилей, PS 5.1 и PS 7
//   2. Журнал Microsoft-Windows-PowerShell/Operational (4104, 4103)
//   3. Журнал PowerShellCore/Operational (4104, 4103)
//   4. Журнал Windows PowerShell (400, 403: запуск/остановка движка)
//   5. Security 4688 (создание процесса powershell/pwsh, нужны права админа)
//   6. Sysmon Event 1 (если установлен)
//   7. Файлы транскриптов PowerShell_transcript.*.txt и Prefetch (косвенные следы)

use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

mod analyzer;

struct Opts {
    since: i64,
    out: Option<String>,
    all: bool,
    max_len: usize,
    tz_min: i64,
    hist_lines: usize,
    only_susp: bool,
}

struct Entry {
    t: i64,
    source: String,
    id: String,
    who: String,
    text: String,
}

// ---------- время ----------

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719468;
    let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn fmt_time(t: i64, tz_min: i64) -> String {
    let l = t + tz_min * 60;
    let days = l.div_euclid(86400);
    let s = l.rem_euclid(86400);
    let (y, m, d) = civil_from_days(days);
    format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02}", y, m, d, s / 3600, (s % 3600) / 60, s % 60)
}

fn now_unix() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// "2026-11-14T19:44:03.123Z" -> unix (UTC)
fn parse_system_time(s: &str) -> Option<i64> {
    parse_civil(&s.replace('T', " ").trim_end_matches('Z').split('.').next()?.to_string())
}

/// "YYYY-MM-DD[ HH:MM[:SS]]" -> unix, как будто это UTC
fn parse_civil(s: &str) -> Option<i64> {
    let s = s.trim().replace('T', " ");
    let mut parts = s.split_whitespace();
    let date = parts.next()?;
    let time = parts.next().unwrap_or("00:00:00");
    let dv: Vec<i64> = date.split('-').filter_map(|x| x.parse().ok()).collect();
    let tv: Vec<i64> = time.split(':').filter_map(|x| x.parse().ok()).collect();
    if dv.len() != 3 || tv.is_empty() {
        return None;
    }
    let (h, mi, se) = (tv[0], *tv.get(1).unwrap_or(&0), *tv.get(2).unwrap_or(&0));
    Some(days_from_civil(dv[0], dv[1], dv[2]) * 86400 + h * 3600 + mi * 60 + se)
}

/// Смещение местного времени от UTC в минутах (спрашиваем у .NET через powershell).
fn local_offset_min() -> Option<i64> {
    let out = Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "[int][TimeZoneInfo]::Local.GetUtcOffset([DateTime]::UtcNow).TotalMinutes",
        ])
        .output()
        .ok()?;
    String::from_utf8_lossy(&out.stdout).trim().parse().ok()
}

/// "30m", "2h", "1d", "1w" или "2026-11-14 20:00" (местное время)
fn parse_since(s: &str, tz_min: i64) -> Result<i64, String> {
    let s = s.trim();
    if let Some(unit) = s.chars().last() {
        let mult = match unit {
            'm' => Some(60),
            'h' => Some(3600),
            'd' => Some(86400),
            'w' => Some(604800),
            _ => None,
        };
        if let (Some(mult), Ok(n)) = (mult, s[..s.len() - 1].parse::<i64>()) {
            return Ok(now_unix() - n * mult);
        }
    }
    parse_civil(s)
        .map(|t| t - tz_min * 60)
        .ok_or_else(|| format!("не понял время '{}'. Примеры: 2h, 1d, \"2026-11-14 20:00\"", s))
}

// ---------- мини-разбор XML ----------

fn unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        rest = &rest[i..];
        if let Some(j) = rest.find(';') {
            let ent = &rest[1..j];
            let rep: Option<String> = match ent {
                "lt" => Some("<".into()),
                "gt" => Some(">".into()),
                "amp" => Some("&".into()),
                "quot" => Some("\"".into()),
                "apos" => Some("'".into()),
                _ if ent.starts_with("#x") => u32::from_str_radix(&ent[2..], 16).ok().and_then(char::from_u32).map(|c| c.to_string()),
                _ if ent.starts_with('#') => ent[1..].parse::<u32>().ok().and_then(char::from_u32).map(|c| c.to_string()),
                _ => None,
            };
            match rep {
                Some(r) => {
                    out.push_str(&r);
                    rest = &rest[j + 1..];
                }
                None => {
                    out.push('&');
                    rest = &rest[1..];
                }
            }
        } else {
            break;
        }
    }
    out.push_str(rest);
    out.replace('\r', "")
}

fn attr_value(xml: &str, tag: &str, attr: &str) -> Option<String> {
    let start = xml.find(tag)?;
    let end = start + xml[start..].find('>')?;
    let head = &xml[start..end];
    let a = head.find(&format!("{}=", attr))?;
    let after = &head[a + attr.len() + 1..];
    let q = after.chars().next()?;
    let inner = &after[1..];
    let close = inner.find(q)?;
    Some(inner[..close].to_string())
}

fn event_id(xml: &str) -> String {
    if let Some(s) = xml.find("<EventID") {
        if let Some(g) = xml[s..].find('>') {
            let b = s + g + 1;
            if let Some(e) = xml[b..].find('<') {
                return xml[b..b + e].trim().to_string();
            }
        }
    }
    String::new()
}

/// Все <Data ...>...</Data> события: (имя или "", значение)
fn parse_data(xml: &str) -> Vec<(String, String)> {
    let mut res = Vec::new();
    let mut rest = xml;
    while let Some(i) = rest.find("<Data") {
        rest = &rest[i + 5..];
        let next = rest.chars().next().unwrap_or(' ');
        if next != ' ' && next != '>' && next != '/' {
            continue;
        }
        let gt = match rest.find('>') {
            Some(g) => g,
            None => break,
        };
        let head = &rest[..gt];
        let name = {
            let fake = format!("<Data{}>", head);
            attr_value(&fake, "<Data", "Name").unwrap_or_default()
        };
        if head.ends_with('/') {
            res.push((name, String::new()));
            rest = &rest[gt + 1..];
            continue;
        }
        let body = &rest[gt + 1..];
        if let Some(e) = body.find("</Data>") {
            res.push((name, unescape(&body[..e])));
            rest = &body[e + 7..];
        } else {
            break;
        }
    }
    res
}

fn get<'a>(data: &'a [(String, String)], name: &str) -> &'a str {
    data.iter().find(|(n, _)| n == name).map(|(_, v)| v.as_str()).unwrap_or("")
}

// ---------- wevtutil ----------

// При выводе в канал wevtutil пишет в системной ANSI-кодировке (на русской Windows
// это cp1251), а не в UTF-8 и не в кодировке консоли, поэтому разбираем байты сами.
#[cfg(windows)]
fn ansi_cp() -> u32 {
    extern "system" {
        fn GetACP() -> u32;
    }
    unsafe { GetACP() }
}

#[cfg(not(windows))]
fn ansi_cp() -> u32 {
    0
}

fn decode_cp(bytes: &[u8], cp: u32) -> String {
    bytes
        .iter()
        .map(|&b| {
            if b < 0x80 {
                return b as char;
            }
            let c = if cp == 1251 {
                match b {
                    0xC0..=0xFF => char::from_u32(0x410 + (b - 0xC0) as u32),
                    0xA8 => Some('Ё'),
                    0xB8 => Some('ё'),
                    0x85 => Some('…'),
                    0x91 => Some('‘'),
                    0x92 => Some('’'),
                    0x93 => Some('“'),
                    0x94 => Some('”'),
                    0x95 => Some('•'),
                    0x96 => Some('–'),
                    0x97 => Some('—'),
                    0xA0 => Some(' '),
                    0xAB => Some('«'),
                    0xBB => Some('»'),
                    0xB9 => Some('№'),
                    _ => None,
                }
            } else {
                match b {
                    0x80..=0xAF => char::from_u32(0x410 + (b - 0x80) as u32),
                    0xE0..=0xEF => char::from_u32(0x440 + (b - 0xE0) as u32),
                    0xF0 => Some('Ё'),
                    0xF1 => Some('ё'),
                    _ => None,
                }
            };
            c.unwrap_or('?')
        })
        .collect()
}

fn decode_output(bytes: &[u8]) -> String {
    match std::str::from_utf8(bytes) {
        Ok(s) => s.to_string(),
        Err(_) => decode_cp(bytes, if ansi_cp() == 866 { 866 } else { 1251 }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cp866_cyrillic() {
        // "Не" и "я" в cp866
        assert_eq!(decode_cp(&[0x8D, 0xA5], 866), "Не");
        assert_eq!(decode_cp(&[0xEF], 866), "я");
        assert_eq!(decode_cp(&[0xCD, 0xE5], 1251), "Не");
    }

    #[test]
    fn utf8_passes_through() {
        assert_eq!(decode_output("Отказано в доступе.".as_bytes()), "Отказано в доступе.");
    }
}

fn query_log(log: &str, ids: &[u32], since: i64) -> Result<Vec<String>, String> {
    let idq = ids.iter().map(|i| format!("EventID={}", i)).collect::<Vec<_>>().join(" or ");
    let age_ms = (now_unix() - since).max(0) * 1000 + 1000;
    let q = format!("*[System[({}) and TimeCreated[timediff(@SystemTime) <= {}]]]", idq, age_ms);
    let out = Command::new("wevtutil")
        .args(["qe", log, &format!("/q:{}", q), "/f:xml", "/rd:false"])
        .output()
        .map_err(|e| format!("не удалось запустить wevtutil: {}", e))?;
    if !out.status.success() {
        let err = decode_output(&out.stderr);
        let err = if err.trim().is_empty() { decode_output(&out.stdout) } else { err };
        let err = err.lines().map(|l| l.trim()).filter(|l| !l.is_empty()).collect::<Vec<_>>().join(" ");
        return Err(err);
    }
    let text = decode_output(&out.stdout);
    Ok(text
        .split("</Event>")
        .filter(|p| p.contains("<Event"))
        .map(|p| p.to_string())
        .collect())
}

fn is_ps_image(s: &str) -> bool {
    let l = s.to_lowercase();
    l.contains("powershell") || l.contains("pwsh")
}

fn collect_scriptblocks(log: &str, label: &str, o: &Opts, entries: &mut Vec<Entry>, notes: &mut Vec<String>) {
    let events = match query_log(log, &[4104, 4103], o.since) {
        Ok(e) => e,
        Err(e) => {
            let hint = if log.contains("PowerShellCore") {
                " (если PowerShell 7 не установлен или не запускался, это нормально)"
            } else {
                ""
            };
            notes.push(format!("{}: {}{}", log, e, hint));
            return;
        }
    };
    struct Block {
        t: i64,
        who: String,
        path: String,
        parts: Vec<(u32, String)>,
    }
    let mut blocks: HashMap<String, Block> = HashMap::new();
    let mut order: Vec<String> = Vec::new();
    for ev in &events {
        let t = attr_value(ev, "<TimeCreated", "SystemTime").and_then(|s| parse_system_time(&s)).unwrap_or(0);
        let id = event_id(ev);
        let who = attr_value(ev, "<Security", "UserID").unwrap_or_default();
        let data = parse_data(ev);
        if id == "4104" {
            let sb_id = get(&data, "ScriptBlockId").to_string();
            let num: u32 = get(&data, "MessageNumber").parse().unwrap_or(1);
            let text = get(&data, "ScriptBlockText").to_string();
            let path = get(&data, "Path").to_string();
            let b = blocks.entry(sb_id.clone()).or_insert_with(|| {
                order.push(sb_id.clone());
                Block { t, who: who.clone(), path, parts: Vec::new() }
            });
            b.parts.push((num, text));
        } else {
            // 4103: Module logging
            let payload = get(&data, "Payload");
            let ctx = get(&data, "ContextInfo");
            let text = if payload.is_empty() { ctx.to_string() } else { format!("{}\n--\n{}", ctx, payload) };
            if !o.all && text.contains("__cmdletization") {
                continue;
            }
            entries.push(Entry { t, source: label.to_string(), id: "4103".into(), who, text });
        }
    }
    for k in order {
        if let Some(mut b) = blocks.remove(&k) {
            b.parts.sort_by_key(|p| p.0);
            let text: String = b.parts.into_iter().map(|p| p.1).collect::<Vec<_>>().join("");
            if !o.all && (text.contains("__cmdletization") || text.contains("Cmdletization.Cim.CimCmdletAdapter")) {
                continue;
            }
            let mut t = text;
            if !b.path.is_empty() {
                t = format!("(файл: {})\n{}", b.path, t);
            }
            entries.push(Entry { t: b.t, source: label.to_string(), id: "4104".into(), who: b.who, text: t });
        }
    }
}

fn collect_classic(o: &Opts, entries: &mut Vec<Entry>, notes: &mut Vec<String>) {
    match query_log("Windows PowerShell", &[400, 403], o.since) {
        Ok(evs) => {
            for ev in evs {
                let t = attr_value(&ev, "<TimeCreated", "SystemTime").and_then(|s| parse_system_time(&s)).unwrap_or(0);
                let id = event_id(&ev);
                let data = parse_data(&ev);
                let joined = data.iter().map(|(_, v)| v.replace('\n', " ")).collect::<Vec<_>>().join(" | ");
                let what = if id == "400" { "движок запущен" } else { "движок остановлен" };
                entries.push(Entry {
                    t,
                    source: "Windows PowerShell".into(),
                    id,
                    who: String::new(),
                    text: format!("{}: {}", what, joined),
                });
            }
        }
        Err(e) => notes.push(format!("Windows PowerShell: {}", e)),
    }
}

fn collect_security(o: &Opts, entries: &mut Vec<Entry>, notes: &mut Vec<String>) {
    match query_log("Security", &[4688], o.since) {
        Ok(evs) => {
            for ev in evs {
                let data = parse_data(&ev);
                let proc_name = get(&data, "NewProcessName");
                if !is_ps_image(proc_name) {
                    continue;
                }
                let t = attr_value(&ev, "<TimeCreated", "SystemTime").and_then(|s| parse_system_time(&s)).unwrap_or(0);
                let cmd = get(&data, "CommandLine");
                let cmd = if cmd.is_empty() { "(командная строка не записана: включите аудит командной строки)" } else { cmd };
                entries.push(Entry {
                    t,
                    source: "Security".into(),
                    id: "4688".into(),
                    who: format!("{}\\{}", get(&data, "SubjectDomainName"), get(&data, "SubjectUserName")),
                    text: format!("{}\n{}\n(родитель: {})", proc_name, cmd, get(&data, "ParentProcessName")),
                });
            }
        }
        Err(e) => notes.push(format!("Security 4688: {} (нужен запуск от администратора)", e)),
    }
}

fn collect_sysmon(o: &Opts, entries: &mut Vec<Entry>, notes: &mut Vec<String>) {
    match query_log("Microsoft-Windows-Sysmon/Operational", &[1], o.since) {
        Ok(evs) => {
            for ev in evs {
                let data = parse_data(&ev);
                if !is_ps_image(get(&data, "Image")) {
                    continue;
                }
                let t = attr_value(&ev, "<TimeCreated", "SystemTime").and_then(|s| parse_system_time(&s)).unwrap_or(0);
                entries.push(Entry {
                    t,
                    source: "Sysmon".into(),
                    id: "1".into(),
                    who: get(&data, "User").to_string(),
                    text: format!("{}\n(родитель: {})", get(&data, "CommandLine"), get(&data, "ParentCommandLine")),
                });
            }
        }
        Err(_) => notes.push("Sysmon: журнал не найден (Sysmon не установлен) или нет доступа".into()),
    }
}

// ---------- файлы ----------

fn mtime(p: &Path) -> Option<i64> {
    fs::metadata(p).ok()?.modified().ok()?.duration_since(UNIX_EPOCH).ok().map(|d| d.as_secs() as i64)
}

fn user_dirs() -> Vec<PathBuf> {
    let drive = env::var("SystemDrive").unwrap_or_else(|_| "C:".into());
    let root = PathBuf::from(format!("{}\\Users", drive));
    fs::read_dir(root)
        .map(|rd| rd.filter_map(|e| e.ok()).map(|e| e.path()).filter(|p| p.is_dir()).collect())
        .unwrap_or_default()
}

fn collect_history_files(o: &Opts, report: &mut String, notes: &mut Vec<String>) {
    report.push_str("\n===== ФАЙЛЫ ИСТОРИИ PSReadLine (без временных меток) =====\n");
    let mut found = false;
    let mut susp_lines: Vec<(String, String, analyzer::Analysis)> = Vec::new();
    for u in user_dirs() {
        let uname = u.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
        let dirs = [
            u.join("AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine"),
            u.join("AppData\\Roaming\\Microsoft\\PowerShell\\PSReadLine"),
        ];
        for d in dirs {
            let rd = match fs::read_dir(&d) {
                Ok(r) => r,
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::PermissionDenied {
                        notes.push(format!("нет доступа к {}", d.display()));
                    }
                    continue;
                }
            };
            for f in rd.filter_map(|e| e.ok()).map(|e| e.path()) {
                let name = f.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
                if !name.to_lowercase().ends_with("_history.txt") {
                    continue;
                }
                found = true;
                let mt = mtime(&f);
                let mts = mt.map(|t| fmt_time(t, o.tz_min)).unwrap_or_else(|| "?".into());
                report.push_str(&format!("\n--- [{}] {}\n    последнее изменение файла: {}", uname, f.display(), mts));
                if let Some(t) = mt {
                    if t < o.since {
                        report.push_str("  (ДО начала периода: команд за период здесь, скорее всего, нет)");
                    }
                }
                report.push('\n');
                match fs::read(&f) {
                    Ok(bytes) => {
                        let text = String::from_utf8_lossy(&bytes).to_string();
                        let lines: Vec<&str> = text.lines().collect();
                        let skip = lines.len().saturating_sub(o.hist_lines);
                        if skip > 0 {
                            report.push_str(&format!("    ... пропущено первых строк: {} (опция --hist-lines)\n", skip));
                        }
                        for l in &lines[skip..] {
                            let an = analyzer::analyze(l);
                            let flagged = an.level > 0;
                            if !o.only_susp || flagged {
                                report.push_str(&format!("    {}{}\n", if flagged { "[!] " } else { "" }, l));
                            }
                            if flagged {
                                susp_lines.push((uname.clone(), l.to_string(), an));
                            }
                        }
                    }
                    Err(e) => report.push_str(&format!("    не удалось прочитать: {}\n", e)),
                }
            }
        }
    }
    if !found {
        report.push_str("(файлов *_history.txt не найдено ни в одном профиле)\n");
    }
    if !susp_lines.is_empty() {
        report.push_str("\n===== ПОДОЗРИТЕЛЬНЫЕ СТРОКИ ИЗ ФАЙЛОВ ИСТОРИИ (время выполнения неизвестно) =====\n");
        for (u, line, an) in &susp_lines {
            report.push_str(&format!("\n[{}] >>> {}\n    {}\n", u, an.level_name(), one_line(line, 300)));
            report.push_str(&describe(an, "    "));
        }
    }
}

fn one_line(s: &str, n: usize) -> String {
    let t: String = s.chars().map(|c| if c == '\n' || c == '\r' { ' ' } else { c }).collect();
    if t.chars().count() > n {
        format!("{}...", t.chars().take(n).collect::<String>())
    } else {
        t
    }
}

fn describe(an: &analyzer::Analysis, ind: &str) -> String {
    let mut s = String::new();
    for f in &an.findings {
        let sev = match f.sev {
            3 => "высокая",
            2 => "средняя",
            _ => "низкая",
        };
        s.push_str(&format!("{}- [{}] {}\n", ind, sev, f.title));
    }
    for d in &an.decoded {
        s.push_str(&format!("{}раскодировано: {}\n", ind, one_line(d, 400)));
    }
    for u in &an.urls {
        s.push_str(&format!("{}URL: {}\n", ind, u));
    }
    s
}

fn collect_traces(o: &Opts, report: &mut String) {
    report.push_str("\n===== КОСВЕННЫЕ СЛЕДЫ (транскрипты, Prefetch) =====\n");
    let mut any = false;
    for u in user_dirs() {
        for sub in ["Documents", "OneDrive\\Documents"] {
            if let Ok(rd) = fs::read_dir(u.join(sub)) {
                for f in rd.filter_map(|e| e.ok()).map(|e| e.path()) {
                    let name = f.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
                    if name.starts_with("PowerShell_transcript.") {
                        if let Some(t) = mtime(&f) {
                            if t >= o.since {
                                any = true;
                                report.push_str(&format!("транскрипт: {}  (изменён {})\n", f.display(), fmt_time(t, o.tz_min)));
                            }
                        }
                    }
                }
            }
        }
    }
    let drive = env::var("SystemDrive").unwrap_or_else(|_| "C:".into());
    if let Ok(rd) = fs::read_dir(format!("{}\\Windows\\Prefetch", drive)) {
        for f in rd.filter_map(|e| e.ok()).map(|e| e.path()) {
            let name = f.file_name().map(|n| n.to_string_lossy().to_uppercase()).unwrap_or_default();
            if (name.starts_with("POWERSHELL.EXE-") || name.starts_with("PWSH.EXE-")) && name.ends_with(".PF") {
                if let Some(t) = mtime(&f) {
                    if t >= o.since {
                        any = true;
                        report.push_str(&format!("prefetch: {}  (последний запуск ~{})\n", name, fmt_time(t, o.tz_min)));
                    }
                }
            }
        }
    }
    if !any {
        report.push_str("(за период ничего не найдено)\n");
    }
}

// ---------- main ----------

fn usage() {
    println!(
        "pshist - сбор истории PowerShell из файла истории, журналов событий, Sysmon и др.

Использование:
  pshist <С_КАКОГО_ВРЕМЕНИ> [опции]

Время:
  2h, 30m, 1d, 1w          относительно сейчас
  \"2026-11-14 20:00\"       местное время

Опции:
  -o, --out ФАЙЛ           сохранить отчёт в файл
  --save                   сохранить в PowerShell_history.txt рядом (в текущей папке)
  --all                    не скрывать служебный шум (cmdletization-модули)
  --only-suspicious        в полном списке показывать только подозрительное
  --max-len N              обрезать блоки скриптов до N символов (по умолчанию 4000)
  --hist-lines N           сколько последних строк брать из ConsoleHost_history (по умолчанию 500)
  --tz-offset МИНУТЫ       смещение местного времени от UTC (по умолчанию определяется само)
  -h, --help               эта справка

Для Security 4688 и чтения чужих профилей запускайте от имени администратора."
    );
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() || args.iter().any(|a| a == "-h" || a == "--help") {
        usage();
        return;
    }
    let mut since_arg: Option<String> = None;
    let mut out: Option<String> = None;
    let mut all = false;
    let mut only_susp = false;
    let mut max_len = 4000usize;
    let mut hist_lines = 500usize;
    let mut tz: Option<i64> = None;
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        let next = |i: &mut usize| -> String {
            *i += 1;
            args.get(*i).cloned().unwrap_or_else(|| {
                eprintln!("у опции {} нет значения", a);
                std::process::exit(2);
            })
        };
        match a {
            "-o" | "--out" => out = Some(next(&mut i)),
            "--save" => out = Some("PowerShell_history.txt".into()),
            "--all" => all = true,
            "--only-suspicious" | "--susp" => only_susp = true,
            "--max-len" => max_len = next(&mut i).parse().unwrap_or(4000),
            "--hist-lines" => hist_lines = next(&mut i).parse().unwrap_or(500),
            "--tz-offset" => tz = next(&mut i).parse().ok(),
            "--since" => since_arg = Some(next(&mut i)),
            _ if since_arg.is_none() => since_arg = Some(a.to_string()),
            _ => {
                eprintln!("неизвестный аргумент: {}", a);
                std::process::exit(2);
            }
        }
        i += 1;
    }
    let tz_min = tz.or_else(local_offset_min).unwrap_or_else(|| {
        eprintln!("[!] не удалось определить часовой пояс, время показано как UTC (используйте --tz-offset)");
        0
    });
    let since = match parse_since(&since_arg.unwrap_or_default(), tz_min) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{}", e);
            std::process::exit(2);
        }
    };
    let o = Opts { since, out, all, max_len, tz_min, hist_lines, only_susp };

    eprintln!("Собираю данные с {} ...", fmt_time(o.since, o.tz_min));
    let mut entries: Vec<Entry> = Vec::new();
    let mut notes: Vec<String> = Vec::new();

    collect_scriptblocks("Microsoft-Windows-PowerShell/Operational", "PS Operational", &o, &mut entries, &mut notes);
    collect_scriptblocks("PowerShellCore/Operational", "PS7 Operational", &o, &mut entries, &mut notes);
    collect_classic(&o, &mut entries, &mut notes);
    collect_security(&o, &mut entries, &mut notes);
    collect_sysmon(&o, &mut entries, &mut notes);
    entries.sort_by_key(|e| e.t);

    let mut report = String::new();
    report.push_str(&format!(
        "Отчёт PowerShell  |  период: {} .. {}  |  часовой пояс: UTC{:+}:{:02}\n",
        fmt_time(o.since, o.tz_min),
        fmt_time(now_unix(), o.tz_min),
        o.tz_min / 60,
        (o.tz_min % 60).abs()
    ));
    let analyses: Vec<analyzer::Analysis> = entries.iter().map(|e| analyzer::analyze(&e.text)).collect();
    let cnt = |lvl: u8| analyses.iter().filter(|a| a.level == lvl).count();
    report.push_str(&format!(
        "\nПодозрительных событий в журналах: высокий {}, средний {}, низкий {}  (эвристика, возможны ложные срабатывания)\n",
        cnt(3),
        cnt(2),
        cnt(1)
    ));

    report.push_str("\n===== ПОДОЗРИТЕЛЬНАЯ АКТИВНОСТЬ (журналы событий) =====\n");
    let mut any_susp = false;
    for (e, an) in entries.iter().zip(analyses.iter()) {
        if an.level == 0 {
            continue;
        }
        any_susp = true;
        report.push_str(&format!(
            "\n[{}] {} #{}  >>> {}\n",
            fmt_time(e.t, o.tz_min),
            e.source,
            e.id,
            an.level_name()
        ));
        report.push_str(&format!("    текст: {}\n", one_line(&e.text, 300)));
        report.push_str(&describe(an, "    "));
    }
    if !any_susp {
        report.push_str("(ничего подозрительного в журналах не найдено)\n");
    }

    let shown = if o.only_susp { analyses.iter().filter(|a| a.level > 0).count() } else { entries.len() };
    report.push_str(&format!("\n===== СОБЫТИЯ ЖУРНАЛОВ (по времени), показано: {} из {} =====\n", shown, entries.len()));
    for (e, an) in entries.iter().zip(analyses.iter()) {
        if o.only_susp && an.level == 0 {
            continue;
        }
        report.push_str(&format!("\n[{}] {} #{}", fmt_time(e.t, o.tz_min), e.source, e.id));
        if an.level > 0 {
            report.push_str(&format!("  [!{}]", an.level_name()));
        }
        if !e.who.is_empty() && e.who != "\\" {
            report.push_str(&format!("  user={}", e.who));
        }
        report.push('\n');
        let total = e.text.chars().count();
        let text: String = if total > o.max_len {
            let cut: String = e.text.chars().take(o.max_len).collect();
            format!("{}\n... [обрезано, всего {} символов]", cut, total)
        } else {
            e.text.clone()
        };
        for l in text.lines() {
            report.push_str(&format!("    {}\n", l));
        }
    }

    collect_history_files(&o, &mut report, &mut notes);
    collect_traces(&o, &mut report);

    if !notes.is_empty() {
        report.push_str("\n===== ЗАМЕЧАНИЯ =====\n");
        for n in &notes {
            report.push_str(&format!("- {}\n", n));
        }
    }

    println!("{}", report);
    if let Some(path) = &o.out {
        match fs::write(path, &report) {
            Ok(_) => eprintln!("Сохранено: {}", path),
            Err(e) => eprintln!("Не удалось сохранить {}: {}", path, e),
        }
    }
}
