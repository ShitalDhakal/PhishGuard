async function AjaxCall(url , data){
    const parm = JSON.stringify(data);
    try{
        let response = await fetch(url, {
            method: 'POST',
            body: parm
        });
        let result = await response.json();
        return result;
    }
    catch(error){
        console.log("Error while making api request");
    }
}
async function AjaxCallWithoutParm(url){
    try{
        let response = await fetch(url);
        let result = await response.json();
        return result;
    }
    catch(error){
        console.log("Error while making api request");
    }
}

async function UserValidation(role){
    let data = await AjaxCallWithoutParm("/getLoginData");
    if(data["id"] == 0 || data['role'] != role){
        alert("You are not logged in as proper role!")
        return false;
    }
    else{
        return true;
    }
}
