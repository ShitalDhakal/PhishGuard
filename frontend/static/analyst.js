$(document).ready(async function(){
    let validate = await UserValidation('analyst');
    if(!validate){
        window.location.href = '/';
    }
});