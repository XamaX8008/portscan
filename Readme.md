## Описание

Данный проект представляет собой инструмент для сканирования открытых портов
на заданном хосте. Инструмент позволяет сканировать порты с использованием
протоколов TCP и UDP в заданном диапазоне портов и распознавать протокол,
используемый на каждом порту.

## Требования
Для запуска инструмента необходим интерпретатор языка Python версии 3.6 или выше.

## Установка
* Склонировать репозиторий:
```
git clone https://github.com/username/repo.git
```
* Перейти в директорию с проектом:
```
cd repo
```
* Установить зависимости:
```
pip install -r requirements.txt
```
## Использование
### Для запуска сканирования необходимо выполнить следующую команду:

На Windows:
```
python portscan.py host [-u] [-t] [-p PORTS [PORTS ...]]
```
На Linux:
```
python3 portscan.py host [-u] [-t] [-p PORTS [PORTS ...]]
```
### где:

* host - IP-адрес или доменное имя хостадля сканирования;
* -u - флаг, указывающий, что нужно сканировать порты с протоколом UDP;
* -t - флаг, указывающий, что нужно сканировать порты с протоколом TCP;
* -p - список номеров портов для сканирования.
* По умолчанию сканирование производится только по протоколу TCP на хосте 
127.0.0.1 в диапазоне портов от 1 до 1024.

Примеры использования:

```
python portscan.py example.com -u -p 80 443 8080
```
```
python portscan.py 127.0.0.1 -t
```


## Заключение
Инструмент portscan позволяет быстро и удобно сканировать открытые порты на
заданном хосте с использованием протоколов TCP и UDP. При необходимости можно
задать список портов для сканирования. Инструмент имеет простой интерфейс и
может быть использован как в командной строке, так и в качестве модуля для
других проектов.