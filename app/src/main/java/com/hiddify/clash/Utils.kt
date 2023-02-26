package com.hiddify.clash

//import cn.hutool.core.codec.Base64
import android.app.Activity
import android.content.Context
import android.net.Uri
import android.widget.Toast
import com.github.kr328.clash.design.R
import com.github.kr328.clash.service.model.Profile
import com.github.kr328.clash.service.util.importedDir
import com.github.kr328.clash.util.withClash
import com.github.kr328.clash.util.withProfile
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import io.github.devatherock.simpleyaml.SimpleYamlOutput
import java.io.File
import java.io.UnsupportedEncodingException
import java.net.URLDecoder
import java.time.LocalDateTime
import java.time.format.DateTimeFormatter
import java.util.*
import kotlin.collections.LinkedHashMap

object Utils {
    fun decodeIfBase64(instr:String):String{
        if (org.apache.commons.codec.binary.Base64.isBase64(instr)){
            try {
                return decodeBase64(instr)
            }catch (e:Exception){
                e.printStackTrace()
            }
        }
        return instr
    }
    fun safeDecodeURLBase64(url: String): String {
        val splt = url.split("://").toTypedArray()
        val schema = splt[0]
        var rest = splt[1].substring(5).replace(' ', '-').replace('/', '_').replace('+', '-')
            .replace("=", "")
//        rest = Base64.decodeStr(rest)
        return "$schema://$rest"
    }
    fun decodeUriIfBase64(url: String): String {
        if(!url.contains("://"))return url
        val splt = url.split("://").toTypedArray()
        var right=splt[1]
        if (splt[1].contains("#")) {
            var splt2=splt[1].split ("#").toTypedArray()
            right = decodeIfBase64(splt2[0])+ "#"+splt2[1]
        }else
            right=decodeIfBase64(right)
        return splt[0]+"://"+ right
    }
    fun decodeBase64WithSchema(url: String): String {
        val splt = url.split("://").toTypedArray()
        return decodeBase64(splt[1])
    }

    fun decodeBase64(instr: String): String {
        return String(org.apache.commons.codec.binary.Base64.decodeBase64(instr))
//        return String(Base64.getDecoder().decode(instr))
    }

    fun splitPluginOpts(plugin: String): Map<String, String> {
        var plugin = plugin
        try {
            plugin = URLDecoder.decode(plugin, "UTF-8")
        } catch (e: UnsupportedEncodingException) {
            e.printStackTrace()
        }
        val query_pairs: MutableMap<String, String> = LinkedHashMap()
        val pairs = plugin.split(";").toTypedArray()
        var i = 0
        for (pair in pairs) {
            val idx = pair.indexOf("=")
            if (idx < 0) {
                if (i == 0) query_pairs["plugin"] = pair.substring(idx + 1) else query_pairs[pair] =
                    "true"
            } else {
                query_pairs[pair.substring(0, idx)] = pair.substring(idx + 1)
            }
            i++
        }
        return query_pairs
    }

    var lasttime=0L
    suspend fun addClashProfile(ctx: Context, instr_: String) {
        try {
            if (System.currentTimeMillis()- lasttime<10000){
                showAlarm(ctx,"You have paste a proxy less than 10 second ago.")
            }
            addClashProfile_imp(ctx,instr_)
        } catch (e:Exception) {
            showExceptionToast(ctx,e)
        }
    }
    suspend fun addClashProfile_imp(ctx: Context, instr_: String) {

        var instr=decodeIfBase64(instr_)
        val formatter = DateTimeFormatter.ofPattern("HH:mm dd/MM/yyyy")
        var strname ="Profile"+ LocalDateTime.now().format(formatter)
        if (instr.contains("\nproxies") && instr.contains("\nrules")){
            //clash string
            add_proxy(ctx, instr, "$strname")
//        Toast.makeText(ctx,"Profile added $strname",Toast.LENGTH_LONG).show()
            showAlarm(ctx,"Profile added $strname","Success")
            return
        }
        val yml: LinkedHashMap<String, Any> = LinkedHashMap()
        yml["mixed-port"] = 7890
        yml["allow-lan"] = false
        yml["log-level"] = "info"
        yml["secret"] = ""
        yml["external-controller"] = "127.0.0.1:9090"
        yml["ipv6"] = false
        yml["mode"] = "rule"
        yml["global-client-fingerprint"] = "chrome"
        yml["dns"]= mutableMapOf(
        "enable" to true,
        "use-hosts" to true,
        "ipv6" to false,
        "enhanced-mode" to "fake-ip",
        "fake-ip-range" to "198.18.0.1/16",
        "listen" to "127.0.0.1:6868",
        "default-nameserver" to mutableListOf(
            "1.1.1.1",
            "8.8.8.8",
            "1.0.0.1",
            "9.9.9.9"
        ),
        "nameserver" to mutableListOf(
            "1.1.1.1#PROXY",
            "8.8.8.8#PROXY",
            "1.0.0.1#PROXY"
            "9.9.9.9#PROXY"
        )
        )
        val proxies: ArrayList<Any> = ArrayList()
        val proxy_providers: LinkedHashMap<String,Any> = LinkedHashMap()
        val proxy_groups: ArrayList<LinkedHashMap<String, Any>> = ArrayList()


        var names = ArrayList<String>()
        var urls = instr.split("\n")

        for (u_ in urls) {
            var u= decodeIfBase64(u_.trim()).trim()
            if (u.startsWith("#"))continue
            u=decodeUriIfBase64(u)
            var pp=ProxyProvider()
            if (pp.canDecode(u)){
                var pparse=pp.decode(u)
                for (item in pparse.entries)
                    proxy_providers[item.key]=item.value
                continue
            }


            val proxyParsers = arrayOf<IProxy>(
                SSProxy(),
                VlessProxy(),
                TrojanGoProxy(),
                VmessProxy(),
                SSRProxy(),
//                HttpProxy(),
                SocksProxy()
            )
            for (parser in proxyParsers) {

                if (parser.canDecode(u)) {
                    try {
                        var proxy = parser.decode(u)
                        proxy["name"]="\"${proxy["name"]}\""
                        names.add(proxy["name"]!!.toString())
                        proxies.add(proxy)
                    } catch (e: Exception) {
                        println("Error! $u")
                        e.printStackTrace()
                        showAlarm(ctx, "Error! $u \n $e")
                    }
                }

            }
        }

        yml["proxies"] = proxies
        var autoGroup = LinkedHashMap<String, Any>()
        var selectGroup = LinkedHashMap<String, Any>()
        autoGroup["name"] = "auto"
        autoGroup["proxies"] = names
        autoGroup["type"] = "url-test"
        autoGroup["url"] = "http://cp.cloudflare.com"
        autoGroup["interval"] = 300

        selectGroup["name"] = "PROXY"
        selectGroup["proxies"] = names
        selectGroup["type"] = "select"
        if (proxy_providers.size>0){
            autoGroup["use"] = proxy_providers.keys.toList()
            selectGroup["use"] = proxy_providers.keys.toList()
        }
        proxy_groups.add(autoGroup)
        proxy_groups.add(selectGroup)
        yml["proxy-groups"] = proxy_groups
        yml["proxy-providers"]=proxy_providers
        yml["rules"] = arrayListOf(
            "IP-CIDR,10.10.0.0/16,PROXY",
            "MATCH,PROXY"
        )


        if (proxy_providers.size == 1)
            strname = proxy_providers.keys.first()
        else if (names.size == 1)
            strname = names[0]
        else if (names.size == 0 && proxy_providers.size==0) {
            showAlarm(ctx, "Can not add Profile. No valid proxy find.", "Error")
            return
        }
        strname=strname.replace("\"","")
        add_proxy(ctx, SimpleYamlOutput.toYaml(yml), "$strname")
//        Toast.makeText(ctx,"Profile added $strname",Toast.LENGTH_LONG).show()
        showAlarm(ctx,"Profile added $strname","Success")
    }

    //    suspend fun addClashProfile_old(ctx :Context,url: String) {
//
//        var out="""
//mixed-port: 7890
//allow-lan: false
//log-level: info
//secret: ""
//external-controller: 127.0.0.1:9090
//ipv6: false
//mode: global
//
//proxies:
//        """
//        var names= ArrayList<String>()
//        var urls=url.split("\n")
//        for (u in urls) {
//            val proxies = arrayOf<IProxy>(SSProxy(),VlessProxy(),TrojanGoProxy())
//            for (proxy in proxies) {
//                if (proxy.decode(u)) {
//                    out += proxy.toClash()
//                    names.add(proxy.name())
//                }
//
//            }
//        }
//
//        out+="""
//proxy-groups:
//   - name: auto
//     proxies:
//       """
//        for (name in names)
//            out+="""
//        - "$name" """
//       out+="""
//     type: url-test
//     url: 'https://www.facebook.com/'
//     interval: 300
//
//   - name: PROXY
//     type: select
//     proxies:
//      - auto
//       """
//        for (name in names)
//            out+="""
//      - "$name" """
//       out+="""
//
//rules:
//  - IP-CIDR,10.10.0.0/16,auto
//  - GEOIP,IR,DIRECT
//  - GEOIP,CN,DIRECT
//  - DOMAIN-SUFFIX,.ir,DIRECT
//  - DOMAIN-SUFFIX,.cn,DIRECT
//  - MATCH,auto
//        """
//
////        val formatter = DateTimeFormatter.ofPattern("HH:mm dd/MM/yyyy")
//        var strname="profile"
//        if (names.size==1)
//            strname=names[0]
//        if (names.size==0)
//            return
//        add_proxy(ctx,out, "$strname")
////        add_proxy(ctx,out.replace("mode: global","mode: rule"), "NotIran-$strname")
//    }
    suspend fun add_proxy(ctx: Context, clashcfg: String, name: String) {


//
//        var file=File.createTempFile("hiddify",".yml")
//        file.writeText(clashcfg)


        withProfile {

            create(Profile.Type.File, name).also {
                var td = ctx.importedDir.parent + "/pending/" + it.toString()

                var t = File("$td/config.yaml")
                t.writeText(clashcfg)

                var uuid = it
                try {
                    commit(it).also {
                        queryByUUID(uuid)?.let { it1 -> setActive(it1) }
                        withClash {
                            patchSelector("PROXY", "auto")
                        }


                    }
                } catch (e: Exception) {
                    showExceptionToast(ctx, e)

                }

            }
        }
    }
//
//    fun parseFromClipboard() {}

    fun showExceptionToast(ctx: Context, e: Exception) {
        showAlarm(ctx, e.toString())
    }

    fun showAlarm(ctx: Context, e: String,title:String="Error") {
        if (ctx is Activity) {
            (ctx as Activity).runOnUiThread {
            MaterialAlertDialogBuilder(ctx)
                .setTitle(title)
                .setMessage(e)
                .setCancelable(true)
                .setPositiveButton(R.string.ok) { _, _ -> }
                .show()
            }
        }
    }

    fun getQueryParamIgnoreCase(uri: Uri, param:String):String?{
        for (p in uri.queryParameterNames) {
            if (param.equals(p,ignoreCase = true))
                return uri.getQueryParameter(p)
        }
        return null
    }
}