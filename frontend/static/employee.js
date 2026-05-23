$(document).ready(async function(){
    let validate = await UserValidation('employee');
    if(!validate){
        window.location.href = '/';
    }
});