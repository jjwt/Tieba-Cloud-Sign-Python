
function juggment_passwordag() {
    if ($("#password").val()==$("#passwordag").val()) {
        passwordag_ok=true;
        return true;
    } else {
        passwordag_ok=false;
        return false;
    }
}

var passwordag_ok=false;

function validate_submit() {
    if (username_ok && password_ok && passwordag_ok) {
        $('#register_submit').removeAttr('disabled');
    } else {
        $("#register_submit").prop("disabled",true);
    }
}
