# Vulnerable: FAS-123
content = request.POST.get(USettings.UEditorUploadSettings.get("scrawlFieldName", "upfile"))
        f = open(filename, 'wb')
        f.write(base64.decodestring(content))
        f.close()
        state = "SUCCESS"
    except Exception as e:
        state = u"写入图片文件错误:%s" % e
    return state
def save_file(request):
