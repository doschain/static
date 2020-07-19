var ua = navigator.userAgent;
$(function () {
    $('.mask-colsed').on('click', function () {
        $(this).parents('.mask-box').hide();
    });
    //判定手机|pc 判定ios|Android
    if (/(iPhone|iPad|iPod|iOS)/i.test(ua)) {
        // iOS
        if(!/Safari/.test(ua)){
            $('.mask').show();
        }
        $('.download').text("免费安装");
        $('.download').click(download_iOS);
    } else if (/(Android)/i.test(ua)) {
        // 安卓端
        var ual = ua.toLowerCase();
        var isWeixin = ual.indexOf('micromessenger') != -1;
        if (isWeixin) {
            $('.mask').show()
        }
        $('.download').text("免费下载");
        $('.download').click(download_Apk);
    } else {
        // PC端
        $('.contain-page').hide();
        $('.pc-box').show();
    }
   
});

function download_iOS(){
    if (location.search.indexOf("udid") > -1) {
        var values = location.search.substr(1).split("&");
        for (var i = 0; i < values.length; i++) {
            var value = values[i];
            if (value.startsWith("udid")) {
                var udid = value.split("=")[1];
                $.ajax("/api/ipa/state?udid=" + udid, {
                    success: function (rs) {
                        if (rs.ret) {
                            window.location.href = "itms-services:///?action=download-manifest&url=https://isign.doschain.org/ipa/" + rs.data;
                        }else{
                            var delay = 60;
                            var inter = setInterval(function(){
                                if(--delay <= 0){
                                    clearInterval(inter);
                                    $('.download').text("尝试下载中...");    
                                    download_iOS()
                                }else{
                                    $('.download').text("软件准备中..."+(delay)+"秒");    
                                }
                            },1000);
                        }
                    }, error: function (rs) {

                    }
                });
                break
            }
        }

    } else {
        window.location.href = "/static/mobileconfig/udid.mobileconfig"
        setTimeout(function () {
            window.location.href = "/static/mobileconfig/embedded.mobileprovision";
        }, 3000);
    }
}

function download_Apk(){
    window.location.href = "http://download.doschain.org:8080/demos/wallet/demos-wallet1.0.7.apk?v=1.0.7";
}