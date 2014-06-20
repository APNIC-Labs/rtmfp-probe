import flash.events.NetStatusEvent;
import flash.events.SecurityErrorEvent;
import flash.net.NetConnection;

class Probe {
    static function main() {
        //flash.Lib.redirectTraces();
        var nc = new NetConnection();
        nc.addEventListener(NetStatusEvent.NET_STATUS, netStatusHandler);
        trace("Connecting...");
        nc.connect(flash.Lib.current.loaderInfo.parameters.url);
    }

    private static function netStatusHandler(event:NetStatusEvent) {
        trace(event.info);
    }
}
