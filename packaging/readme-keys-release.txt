■ 情报源 API Key 需要你自己申请

  本包【不含任何 API 密钥】。情报源额度是按账号计费的,把开发者的 Key
  随包分发等于让所有使用者共用同一份额度,几天就会被打满,然后每个人的
  云查都失效。所以密钥留空,由你自己填。

  没有 Key 也能正常运行:缺 Key 的源自动禁用并 fail-open(返回 Unknown),
  本地启发式规则、行为链检测和内核前拦截【完全不受影响】。云查只是加分项。

  两种填法,优先级从高到低:

    · 环境变量(推荐,不写进文件):
        BULWARK_VT_APIKEY          VirusTotal
        BULWARK_MB_AUTHKEY         MalwareBazaar (abuse.ch)
        BULWARK_OTX_APIKEY         AlienVault OTX
        BULWARK_THREATBOOK_APIKEY  微步在线
        BULWARK_MDC_APIKEY         MetaDefender Cloud
        BULWARK_HA_APIKEY          Hybrid Analysis
        BULWARK_ABUSECH_AUTHKEY    ThreatFox(留空则回退用 MalwareBazaar 的)
        BULWARK_AI_APIKEY          大模型(OpenAI 兼容)

      以服务(SYSTEM)身份运行时,环境变量要设成【系统级】—— 用户级变量
      SYSTEM 读不到。

    · 界面里的「情报源设置」逐源填写(最方便,热更、立即生效,
      落在 %ProgramData%\Bulwark\settings.json)

  申请地址都是免费档:
    VirusTotal      https://www.virustotal.com/gui/join-us
    abuse.ch        https://auth.abuse.ch/        (MalwareBazaar + ThreatFox 共用)
    OTX             https://otx.alienvault.com/
    MetaDefender    https://www.opswat.com/products/metadefender/cloud
    Hybrid Analysis https://www.hybrid-analysis.com/

  VirusTotal 支持一次配多个 Key(英文逗号分隔),每个 Key 独立计账、额度
  真正叠加;某个 Key 触发限流(429)或失效(401)会自动冷却跳到下一个。
