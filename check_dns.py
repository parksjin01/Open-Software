import urllib2
import BeautifulSoup

def checking_ip(ip_address):
    scores={'Low Risk':1, 'Medium Risk':2, 'High Risk':5}
    score_sum=0
    a=urllib2.urlopen('https://sitecheck.sucuri.net/results/'+ip_address)
    html=BeautifulSoup.BeautifulSoup(a)
    result=html.findAll('table', attrs={'class':'table scan-findings'})
    result=result[0].findAll('td')
    if result[2]=='Critical':
        return 0
    for i in range(len(result)/4):
        try:
            print result[i*4+2].text
            score_sum+=scores[result[i*4+2].text]
        except:
            score_sum+=10
    print score_sum
    return score_sum

def making_blacklist():
    with open('test.txt', 'rt') as f:
        with open('blacklist.txt', 'wt') as b:
            ips=f.read().split(' ')
            for ip in ips[:-1]:
                dangerous_score=checking_ip(ip)
                if dangerous_score>20:
                    b.write(ip+' ')

making_blacklist()