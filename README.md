# cross-platform-format-quest-v1 (CPFQ-v1)

This format will be used for migartion quests between different CTF-systems.

Ver. 1 (2017)


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

## Package structure

### For developers/organizators

* Folder `private` - contains files for developers of quest
* File `deploy.md` - description of "How to prepare infostructure or how to regenerate files for quest"
* File `solve.md` - description for how to solving quest

### For import to system

* File `main.json` - data for import to system. For check just run: `python3 cpfq-v1.py check <path-to-folder>`
* File `README.md` - in human information. You can use for autogenerate `python3 cpfq-v1.py update_readme <path-to-folder>`

### categories:

 - admin
 - crypto
 - enjoi or joi
 - reverse
 - stegano
 - ppc
 - web
 - recon
 - forensics
 - hashes
 - ctd - ???

In folder `example` you can see correct format of task.

## How to fill main.json

Please copy folder `example` and change inside. After this: `python3 cpfq-v1.py check <path-to-folder>`

Or  run `python3 cpfq-v1.py create <path-to-folder>` and follow instructions

## Recomendations:

Please fill enough information for understand outside developers. And ofcause contact with developers/organizators.


