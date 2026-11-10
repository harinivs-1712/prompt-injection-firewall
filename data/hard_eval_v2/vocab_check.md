# Vocabulary leakage check

Computed over fully-contained attack segments (2,224 word tokens) versus harmless segments (6,918 word tokens); partial-overlap windows excluded. Simple smoothed log-odds with alpha=0.5. Positive scores associate with attack; negative scores associate with harmless. This is descriptive, not a causal leakage test.

## 20 words most associated with attack

| Word | Log-odds | Attack count | Harmless count |
|---|---:|---:|---:|
| private | 4.543 | 16 | 0 |
| recovery | 3.991 | 9 | 0 |
| phrase | 3.879 | 8 | 0 |
| string | 3.754 | 7 | 0 |
| shown | 3.754 | 7 | 0 |
| requester | 3.754 | 7 | 0 |
| qa | 3.754 | 7 | 0 |
| belongs | 3.754 | 7 | 0 |
| user | 3.611 | 6 | 0 |
| routing | 3.611 | 6 | 0 |
| omit | 3.611 | 6 | 0 |
| message | 3.611 | 6 | 0 |
| service | 3.243 | 4 | 0 |
| say | 3.243 | 4 | 0 |
| into | 3.243 | 4 | 0 |
| instruction | 3.243 | 4 | 0 |
| appendix | 3.243 | 4 | 0 |
| while | 2.992 | 3 | 0 |
| web | 2.992 | 3 | 0 |
| transfer | 2.992 | 3 | 0 |

## 20 words most associated with harmless

| Word | Log-odds | Attack count | Harmless count |
|---|---:|---:|---:|
| group | -2.450 | 0 | 16 |
| questions | -2.321 | 0 | 14 |
| chart | -2.173 | 0 | 12 |
| organizer | -2.173 | 0 | 12 |
| use | -2.173 | 0 | 12 |
| was | -2.173 | 0 | 12 |
| count | -1.998 | 0 | 10 |
| planned | -1.998 | 0 | 10 |
| room | -1.998 | 0 | 10 |
| two | -1.998 | 0 | 10 |
| coordinator | -1.898 | 0 | 9 |
| covers | -1.898 | 0 | 9 |
| month | -1.898 | 0 | 9 |
| small | -1.898 | 0 | 9 |
| start | -1.898 | 0 | 9 |
| three | -1.898 | 0 | 9 |
| agenda | -1.787 | 0 | 8 |
| each | -1.787 | 0 | 8 |
| included | -1.787 | 0 | 8 |
| will | -1.787 | 0 | 8 |
