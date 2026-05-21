$(document).ready(async function(){
    let validate = await UserValidation('admin');
    if(!validate){
        window.location.href = '/';
    }
});