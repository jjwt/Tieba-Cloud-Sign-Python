function deltbuser(obj) {
    var r=confirm("解绑会删除该贴吧用户的所有信息，包括贴吧列表，签到记录等。该操作不可恢复，确定要解绑吗？");
    if (r == true) {
        $(document).ready(function(){
            $.ajax({
                url:"/deltbuser",
                async:false,
                dataType:"json",
                type:'POST',
                data:{
                    'tbuid': $(obj).attr("tbuid"),
                },
                success: function(x) {
                    alert(x['err_msg']);
                },
                error: function(x) {
                    alert("操作失败，发生未知错误!");
                }
            });
        });
    }
}
function signrecords(obj) {
    $(document).ready(function(){
        $.ajax({
            url:"/signrecords",
            async:false,
            dataType:"html",
            type:'POST',
            data:{
                'tbuid': $(obj).attr("tbuid"),
                'pn': $(obj).attr("pn"),
            },
            success: function(x) {
                $('#signrecords').html(x);
            },
            error: function(x) {
                $("#span_err_msg").html("操作失败，发生未知错误!");
                $("#div_err_msg").show();
            }
        });
    });
}
function tblist(obj) {
    $(document).ready(function(){
        $.ajax({
            url:"/tblist",
            async:false,
            dataType:"html",
            type:'POST',
            data:{
                'tbuid': $(obj).attr("tbuid"),
                'pn': $(obj).attr("pn"),
            },
            success: function(x) {
                $('#tblist').html(x);
            },
            error: function(x) {
                $("#span_err_msg").html("操作失败，发生未知错误!");
                $("#div_err_msg").show();
            }
        });
    });
}
function firstpage() {
    $(document).ready(function(){
        $.ajax({
            url:"/firstpage",
            async:false,
            dataType:"html",
            type:'GET',
            success: function(x) {
                $('#content').html(x);
            },
            error: function(x) {
                $("#span_err_msg").html("操作失败，发生未知错误!");
                $("#div_err_msg").show();
            }
        });
    });
}
function addtbuser_get() {
    $(document).ready(function(){
        $.ajax({
            url:"/addtbuser",
            async:false,
            dataType:"html",
            type:'GET',
            success: function(x) {
                $('#content').html(x);
            },
            error: function(x) {
                $("#span_err_msg").html("操作失败，发生未知错误!");
                $("#div_err_msg").show();
            }
        });
    });
}
function addtbuser_post() {
    $(document).ready(function(){
        $.ajax({
            url:"/addtbuser",
            async:false,
            dataType:"json",
            type:'POST',
            data:{
                'tbuser_name': $("#tbuser_name").val(),
                'tbuser_pw': $("#tbuser_pw").val(),
                'verifycode': $("#verifycode").val(),
                'vcodestr': $("#vcodestr").val()
            },
            success: function(x) {
                if (x["err_no"]!="0") {
                    $("#span_err_msg").html(x["err_msg"]);
                    $("#div_err_msg").show();
                } else {
                    $("#content").html(x["err_msg"]);
                    $("#addtbuser_get")
                    var $a=$('<a></a>');
                    $a.attr("class", "list-group-item");
                    $a.attr("onclick", "ch_active(this);tbuser(this);return false;");
                    $a.attr("id", "tbuid"+x["tbuser_id"]);
                    $a.attr("tbuid", x["tbuser_id"]);
                    $a.text(x["tbuser_name"]);
                    $a.insertBefore($("#add_tbuser_get"));
                }
            },
            error: function(x) {
                $("#span_err_msg").html("操作失败，发生未知错误!");
                $("#div_err_msg").show();
            }
        });
    });
}

function tbuser(obj) {
    $(document).ready(function(){
        $.ajax({
            url:"/tbuser",
            async:false,
            dataType:"html",
            type:'POST',
            data:{
                'tbuid': $(obj).attr("tbuid"),
            },
            success: function(x) {
                $('#content').html(x);
            },
            error: function(x) {
                $('#content').html("操作失败，发生未知错误!");
            }
        });
    });
}

function get_vcode() {
    $("#span_err_msg").html("正在刷新验证码...");
    $("#div_err_msg").show();
    $(document).ready(function(){
        $.ajax({
            url:"/getvercode",
            async:true,
            dataType:"json",
            type:'POST',
            data:{
                'tbuser_name': $("#tbuser_name").val(),
            },
            complete: function(x,y) {
                $('#addbdid_prog').css({"display":"none"});
                $('#addbdid_submit').removeAttr('disabled');
            },
            success: function(x) {
                if (x["err_no"]=="0") {
                    $("#span_err_msg").html("拉取成功,请输出图中的验证码,点击图片刷新验证码");
                    $("#div_err_msg").show();
                    $("#vcode_img").attr("src","http://wappass.baidu.com/cgi-bin/genimage?"+x["vcodestr"]);
                    $("#vcodestr").attr("value",x["vcodestr"]);
                } else {
                    $("#span_err_msg").html(x['err_msg']);
                    $("#div_err_msg").show();
                    
                }
            },
            error: function(x) {
                $("#vcode_msg").html("操作失败，发生未知错误!");
            }
        });
    });
}
