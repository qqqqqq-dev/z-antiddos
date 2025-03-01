# Z-ANTIDDOS service for Battlefield 3 & 4

## English

### Description

This service allows mitigating any UDP attacks on zloemu game servers. Since Battlefield game servers are very unstable when receiving large amounts of junk packets, we've created a solution that drops all packets at the firewall level. With our service, the server port is only accessible to those who are actually connecting to the server through zloemu.

### Installation Instructions

1. Download the ZServerInterface.dll library
2. Place it in the same folder as ZServer.exe
3. Make sure Windows Firewall is enabled
4. Make sure your firewall's current policy blocks all incoming connections by default

### Requirements

You need to have any version of MinGW WinLibs Personal Build installed:
- MinGW-w64 msvcrt 12.0.0-r3 with posix

### Credits

- well dev (qqqqqq-dev)
- zlofenix

## Русский

### Описание

Эта служба позволяет мигрировать и смягчать любые UDP атаки на игровые сервера zloemu. Так как сервер игр Battlefield очень неустойчив при получении большого количества мусорных пакетов, мы создали решение, которое будет отбрасывать все пакеты на уровне firewall. C нашей службой, порт сервера доступен только для тех, кто реально подключается на сервер через zloemu.

### Инструкция по установке

1. Скачайте библиотеку ZServerInterface.dll
2. Поместите её в папку с ZServer.exe
3. Убедитесь, что брандмауэр Windows включен
4. Убедитесь что текущая политика вашего firewall по дефолту запрещает все входящие подключения

### Требования

Необходимо иметь установленной версию MinGW:
- MinGW-w64 msvcrt 12.0.0-r3 with posix

### Авторы

- well dev (qqqqqq-dev)
- zlofenix
