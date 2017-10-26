window.onload = function() {
    assignButtons();
}

function assignButtons() {
    $(".delete-credential").click(function(){    
        deleteCredential(this);
        return false;
    });
    $
}

function deleteCredential(credential) {
    console.log($(credential));
    let credId = $(credential).data("cred");
    $.ajax({
        url: '/credential/' + credId,
        type: 'DELETE',        
        success: function(result) {
            removeCredential(credential);
        }
    });
}

function removeCredential(credential) {
    var $credContainer = $(credential).parent();
    $credContainer.fadeOut( 1000, "linear");
}