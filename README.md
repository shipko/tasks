```
example
├── deploy.md
├── main.json
├── private
│   ├── prepare.sh
│   ├── requirements.txt
│   ├── run.py
│   ├── static
│   │   └── flag.txt
│   └── templates
├── public
│   └── run.py
├── README.md
└── solve.md
```

## Структура задания.
Папка с названием задания. Её содержание:

1) Папка private. В ней исходные файлы задания для команды разработчиков.

2) Папка public. В ней файлы для участников соревнований, которые им будет предложено скачать.

3) Файл deploy.md. В нём информация для разработчиков как правильно настроить инфраструктуру для задания.

4) Файл solve.md. В нём информация о там как привильно решать задание.

5) Файл main.json. В нём конфигурационная информация для автоматического добавления задания, заполни его верно и проверь валидность файла [тут](http://jsonlint.com/).

6) Файл README.md. В нём информация из main.json только в читаемом виде.

Доступные категории: admin, joy, ctb, reverse, stegano, ppc, crypto, web.

Внутри конфигурационного файла указывать категорию из списка выше. Просто берете и копируете из списка, не надо менять регистр и т.д. и т.п.

В папке example приведен пример правильно оформленного задания.

## Рекомендации

1) Заполняйте всё максимально понятно.

2) Если для решения используются специальные тулзы, статьи, скрипты, оставляйте ссылки в поле "special field" README.md

3) TODO

P.s. по всем вопросам в [VK](https://vk.com/iseption) или в [Telegram](https://telegram.me/iseption)
