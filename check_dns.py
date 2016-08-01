import urllib2
import BeautifulSoup
a=urllib2.urlopen('https://sitecheck.sucuri.net/results/'+raw_input())
html=BeautifulSoup.BeautifulSoup(a)
result=html.findAll('table', attrs={'class':'table scan-findings'})
result=result[0].findAll('td')
for i in range(len(result)/4):
    print result[i*4].text, result[i*4+1].text, result[i*4+2].text, result[i*4+3].text

