function adduser()
{
    var o=document.getElementById("add_user");
    o.innerHTML+='<p>用户名: <input id="bd_name" type="text" name="username" /></p>';
    o.innerHTML+='<p>密  码: <input id="bd_pw" type="password" name="password" /></p>';
    o.innerHTML+='<input type="button" name="" value="获取验证码" onclick="$(this).remove();add_vcode();" />';
    o.innerHTML+='<p><span id="vcode_msg"></span></p>';
    o.innerHTML+='<div id="add_user2"></div>';
}
function add_vcode() {
    $("#vcode_msg").html("正在拉取验证码...");
    $(document).ready(function(){
        $.ajax({
            url:"/getvercode",
            async:true,
            dataType:"json",
            type:'POST',
            data:{
                'bd_name': $("#bd_name").val()
            },
            complete: function(x,y) {
                $('#addbdid_prog').css({"display":"none"});
                $('#addbdid_submit').removeAttr('disabled');
            },
            success: function(x) {
                $('#vcode_msg').html("拉取成功,请输出图中的验证码,点击图片刷新验证码");
                var o=document.getElementById("add_user2");
                o.innerHTML+='<p><img id="vcode_img" onclick="change_vcode();" />';
                o.innerHTML+='<input id="bd_vcodestr" type="hidden" name="vcodestr">';
                o.innerHTML+='<input id="verifycode" type="text"></p>';
                o.innerHTML+='<input type="button" id="btn_addtbuser" value="绑定" onclick="add_tbuser();" />';
                $("#bd_vcodestr").attr("value",x["vcodestr"]);
                $("#vcode_img").attr("src","http://wappass.baidu.com/cgi-bin/genimage?"+x["vcodestr"]);
            },
            error: function(x) {
                $("#vcode_msg").html("操作失败，发生未知错误!");
            }
        });
    });
}
function change_vcode() {
    $("#vcode_msg").html("正在刷新验证码...");
    $(document).ready(function(){
        $.ajax({
            url:"/getvercode",
            async:true,
            dataType:"json",
            type:'POST',
            data:{
                'bd_name': $("#bd_name").val()
            },
            complete: function(x,y) {
                $('#addbdid_prog').css({"display":"none"});
                $('#addbdid_submit').removeAttr('disabled');
            },
            success: function(x) {
                $('#vcode_msg').html("刷新成功,请输出图中的验证码,点击图片刷新验证码");
                $("#bd_vcodestr").attr("href",x["vcodestr"]);
                $("#vcode_img").attr("src","http://wappass.baidu.com/cgi-bin/genimage?"+x["vcodestr"]);
            },
            error: function(x) {
                $("#vcode_msg").html("操作失败，发生未知错误!");
            }
        });
    });
}
function add_tbuser() {
    $("#vcode_msg").html("正在绑定...");
    $("#btn_addtbuser").prop("disabled",true);
    $(document).ready(function(){
        $.ajax({
            url:"/addtbuser",
            async:true,
            dataType:"json",
            type:'POST',
            data:{
                'bd_name': $("#bd_name").val(),
                'bd_pw': $("#bd_pw").val(),
                'verifycode': $("#verifycode").val(),
                'bd_vcodestr': $("#bd_vcodestr").val()
            },
            complete: function(x,y) {
                $("#btn_addtbuser").prop("disabled",false);
            },
            success: function(x) {
                //$('#vcode_msg').html("绑定成功");
                if (x["err_no"]=="0") {
                    alert("绑定成功,本窗口关闭后将刷新页面");
                    location.reload();
                } else {
                    $("#vcode_msg").html("操作失败，发生未知错误!");
                    
                }
            },
            error: function(x) {
                $("#vcode_msg").html("操作失败，发生未知错误!");
            }
        });
    });
}

/*
 * function toggle_icon(juggment)
 * 提示用户输入合法性
 * 输入错误时，切换为ok图标
 * 输入正确时，切换为error图标
 */
function toggle_icon(span_id,juggment) {
    if (juggment) {
        $(span_id).attr("class","glyphicon glyphicon-ok form-control-feedback");
    } else {
        $(span_id).attr("class","glyphicon glyphicon-remove form-control-feedback");
    }
    validate_submit();
}

/*
 * 判断输入合法性
 * false 非法
 * true 合法
 */
function juggment_user(content) {
    //长度 4-8
    if ((content.length<4) || (content.length>8)) {
        return false;
    }
    //没有空白符
    if (content.search(/\s/)!=-1) {
        return false;
    }
    username_ok=true;
    return true;
}

function juggment_password(content) {
    //长度 6-18
    if ((content.length<6) || (content.length>16)) {
        return false;
    }
    //字母和数字组合
    var has_char=false;
    var has_digit=false;
    for (var i=0; i < content.length; ++i) {
        if (content[i].match(/\d/)) {
            has_digit=true;
        } else if (content[i].match(/[a-zA-Z]/)){
            has_char=true;
        } else {
            return false;
        }
    }
    if (has_char && has_digit) {
        password_ok=true;
        return true;
    }
}

var username_ok=false;
var password_ok=false;
