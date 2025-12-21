## DumpChromeSecrets

Extract data from modern Chrome versions, including refresh tokens, cookies, saved credentials, autofill data, browsing history, and bookmarks. 

<br>

### Quick Links

[Maldev Academy Home](https://maldevacademy.com?ref=gh)

[Maldev Database](https://search.maldevacademy.com?ref=gh)
  
[Malware Development Course Syllabus](https://maldevacademy.com/maldev-course/syllabus?ref=gh)

[Offensive Phishing Operations Course Syllabus](https://maldevacademy.com/phishing-course/syllabus?ref=gh)

[Ransomware Internals, Simulation and Detection Course Syllabus](https://maldevacademy.com/ransomware-course/syllabus?ref=gh)

<br>

### How Does It Work

This project consists of two components:

1. **Executable (`DumpChromeSecrets.exe`)** - Creates a headless Chrome process, injects the DLL via [Early Bird APC injection](https://attack.mitre.org/techniques/T1055/004/), and receives extracted data through a named pipe.

2. **DLL (`DllExtractChromeSecrets.dll`)** - Runs inside Chrome's process context to decrypt the App-Bound encryption key using Chrome's `IElevator` COM interface, then extracts and decrypts data from SQLite databases.

<br>

### Chrome's App-Bound Encryption (v127+)

Starting with Chrome 127, Google introduced App-Bound Encryption, which ties cookie encryption keys to the Chrome application identity. The encryption key (named `"app_bound_encrypted_key"`) is stored in the `"Local State"` file, and can be decrypted by Chrome's elevation service via the `IElevator` COM interface.

This project bypasses this protection by injecting code into Chrome's process, allowing it to call `IElevator::DecryptData` with the proper application context. Another method was implemented by [luci4](https://github.com/l00sy4) in the [Dumping Browser Cookies: Chrome](https://maldevacademy.com/new/modules/81) and [Dumping Saved Logins: Chrome](https://maldevacademy.com/new/modules/82) modules.

<img width="1416" height="919" alt="image" src="https://github.com/user-attachments/assets/dc18372e-882d-4ed5-91cd-2378d60f0ee4" />

> *The above image was taken from: [Improving the security of Chrome cookies on Windows](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html)* 

<br>
<br>

### Data Extraction

Once the DLL is injected, it extracts the following data from Chrome:

| **Data Type**      | **Database Path**                     | **Format** | **Encryption**    |
|--------------------|---------------------------------------|------------|-------------------|
| **App-Bound Key**  | `User Data\Local State`               | JSON       | DPAPI + IElevator |
| **Cookies**        | `User Data\Default\Network\Cookies`   | SQLite     | AES-256-GCM (v20) |
| **Logins**         | `User Data\Default\Login Data`        | SQLite     | AES-256-GCM (v20) |
| **Tokens**         | `User Data\Default\Web Data`          | SQLite     | AES-256-GCM (v20) |
| **Autofill**       | `User Data\Default\Web Data`          | SQLite     | None              |
| **History**        | `User Data\Default\History`           | SQLite     | None              |
| **Bookmarks**      | `User Data\Default\Bookmarks`         | JSON       | None              |


<br>

### Usage

```
Usage: DumpChromeSecrets.exe [options]

Options:
  /o <file>    Output JSON File (default: ChromeData.json)
  /all         Export All Entries (default: max 16 per category)
  /?           Show This Help Message

Examples:
  DumpChromeSecrets.exe                        Extract 16 Entry To ChromeData.json
  DumpChromeSecrets.exe /all                   Export All Entries
  DumpChromeSecrets.exe /o Output.json /all    Extract All To Output.json
```

<br>


### Credits

* **IElevator COM interface research from [snovvcrash's gist](https://gist.github.com/snovvcrash/caded55a318bbefcb6cc9ee30e82f824)**
* **[luci4](https://github.com/l00sy4) for technical guidance**
* **SQLite amalgamation from [sqlite.org](https://www.sqlite.org/amalgamation.html)**

<br>

### Demo

<img width="1432" height="689" alt="image" src="https://github.com/user-attachments/assets/bb12eaaf-caba-4aed-91dc-51ce5bf516d0" />

<br>
