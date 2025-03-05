על מנת לשמור מפתחות הגדרנו משתנה SSLKEYLOGFILE ושמרנו אותו בקובץ ~/.bashrc
בווירשארק הגדרנו שיפענח את TLS באמצעות המשתנה SSLKEYLOGFILE שהגדרנו.
לצורך הנוחות יש הקלטה נפרדת לכל אפליקציה ודפדפן בנפרד.

אלה כל הספריות שהשתשמנו בהם:
import matplotlib.pyplot as plt
from scapy.layers.inet import IP, TCP
import pandas as pd
from scapy.all import rdpcap
from scapy.layers.tls.all import TLS
from pathlib import Path

matplotlib – עבור הדפסת הגרפים. עשינו import  ישירות.
scapy – עבור פיענוח הפקטות מויירשארק, עשינו import  ישירות.
Pathlib – על מנת שנוכל לגשת להקלטות ישירות מהפרויקט ולא להשתמש בpath אבסולוטי גם עשינו mpot ישיריות מpython.
וcryptography Python module-  על מנת להוריד נא להריץ בטרמינל את:
py -m pip install cryptography

השתמשנו בגרסת python 3.12- ואלו חבילות שהתשמנו בהם.
 
הקבצי pcapng כבר נמצאים בגיט ואצרף גם במקרה הצורך בזיפ או אעלה לdrive. הקוד רץ עם קבתיח pcapng.

