import AUtils
import ProxyMain
import Registration
import AgentMain


Registration.ssl_registration()

while True:
    behavior_type = AUtils.get_behavior_type()
    if behavior_type == "agent":
        AgentMain.agent_main()

    elif behavior_type == "error":
        AUtils.set_behavior_type("agent")
        break

    elif behavior_type == "proxy":
        ProxyMain.proxy_main()


