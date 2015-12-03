function ch_active(obj) {
    $(obj).siblings().attr("class","list-group-item");
    $(obj).attr("class","list-group-item active");
}
function ch_tab(obj) {
    var o1=$(obj).parent();
    o1.siblings().attr("class","");
    o1.attr("class","active");
    var o2=$(document.getElementById($(obj).attr("tid")));
    o2.siblings().attr("class","tab-pane");
    o2.attr("class","tab-pane active");
}
