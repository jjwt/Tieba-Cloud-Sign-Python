function validate_submit() {
    if (username_ok && password_ok) {
        $('#submit').removeAttr('disabled');
    } else {
        $("#submit").prop("disabled",true);
    }
}
