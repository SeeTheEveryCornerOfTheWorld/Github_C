#include "xmlOperate.h"

#include "commonDefine.h"
#include "commonHead.h"
#include "commonFunc.h"
#include "log.h"

#include <libxml/parser.h>
#include <libxml/tree.h>

// trim from start 
static inline std::string& ltrim(std::string& s) {
	s.erase(s.begin(), std::find_if(s.begin(), s.end(), std::not1(std::ptr_fun<int, int>(std::isspace))));
	return s;
}

// trim from end 
static inline std::string& rtrim(std::string& s) {
	s.erase(std::find_if(s.rbegin(), s.rend(), std::not1(std::ptr_fun<int, int>(std::isspace))).base(), s.end());
	return s;
}

static inline std::string& trim(std::string& s) {
	return ltrim(rtrim(s));
}

int parse_value(char* str, char** key, char** value)
{
	char* p = NULL;
	int len = 0, i;

	*key = str;
	if ((p = strchr(str, '=')) == NULL)
	{
		printf("invalid key value:%s\n", str);
		return -1;
	}

	*p = 0;
	*value = p + 1;

	while (**value == ' ' || **value == '\t')
	{
		(*value)++;
	}

	len = strlen(str);
	for (i = len - 1; i > 0; i--)
	{
		if ((*key)[len] == ' ' || (*key)[len] == '\t')
			(*key)[len] = '\0';
	}

	return 0;
}


/**********************************************************************
��������: readBasicInfo
��������: ���ػ���������Ϣ
�������:
�������:
�� �� һ: zkxaInfo, ������Ϣ�ṹ
��    �أ�0�ɹ���-1ʧ��
��    ��: ����Ԩ
����ʱ��: 20200917
**********************************************************************/
int readBasicInfo(SzkxaInfo& zkxaInfo)
{
	int ret = 0;
	FILE* fd;
	char buf[1024], * pz;
	char* key = NULL, * value = NULL;

	if ((fd = fopen(GSI_CFG, "rb")) == NULL)
	{
		log_error_fmt("open %s failed! %d:%s\n", GSI_CFG, errno, strerror(errno));
		return -1;
	}

	zkxaInfo.strEth = SWAP_DEV;

	while (fgets(buf, sizeof(buf), fd) != NULL)
	{
		if (buf[0] == '#')
			continue;

		if (strlen(buf) < 3) //����С��3�϶��ǷǷ�����
			continue;

		if ((pz = strchr(buf, 0x0D)) != NULL || (pz = strchr(buf, 0x0A)) != NULL)
			*pz = '\0';

		if (parse_value(buf, &key, &value))
			continue;

		if (!strncmp(key, "datasource.url", strlen("datasource.url")))
		{
			char szUrl[256] = { 0 };
			char szAddr[32] = { 0 };
			char szDbname[100] = { 0 };
			int port = 0;
			sscanf(value, "%*[^/]//%[^?]", szUrl);
			sscanf(szUrl, "%[0-9.]:%d/%s", szAddr, &port, szDbname);
			if (port == 0)
			{
				port = 3306;
				sscanf(szUrl, "%[0-9.]/%s", szAddr, szDbname);
			}
			zkxaInfo.strDbServerIp = szAddr;
			zkxaInfo.nDbServerPort = port;
			zkxaInfo.strDbName = szDbname;
		}
		else if (!strncmp(key, "datasource.username", strlen("datasource.username")))
			zkxaInfo.strDbUser = value;
		else if (!strncmp(key, "datasource.password", strlen("datasource.password")))
			zkxaInfo.strDbPass = value;

		else if (!strncmp(key, "gsi.config.tasOrUas", strlen("gsi.config.tasOrUas")))
		{
			if (!strncmp(key, "gsi.config.tasOrUasStr", strlen("gsi.config.tasOrUasStr")))
			{
				continue;
			}
			if (!strncmp(value, "1", 1))
				zkxaInfo.chType = 'T';
			else
				zkxaInfo.chType = 'U';
		}
		else if (!strncmp(key, "gsi.config.tas.host", strlen("gsi.config.tas.host")))
		{
			zkxaInfo.strInetTasIp = value;
		}
		else if (!strncmp(key, "gsi.config.uas.host", strlen("gsi.config.uas.host")))
		{
			zkxaInfo.strInetUasIp = value;
		}
	}

	return ret;
}




