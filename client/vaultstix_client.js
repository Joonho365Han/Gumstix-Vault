$(function(){

	var updateFilelist = function(){

		// List stored
		var connection = new WebSocket("ws://10.0.0.100:81");
		connection.onopen = function () { connection.send(JSON.stringify({
			data: "U"
		})); };
		connection.onmessage = function (e) {

			console.log(e);
			var files = JSON.parse(e);
			var txt = "";
			for (var i = 0; i < files.length; i++)
			{
				txt += files[i] + "<br>";
			}
			//  List files on vaultstix
			document.getElementById("encryptedFiles").innerHTML = txt;
		};
		connection.onerror = function (error) { alert('Error: websocket connection failed: ' + error); };
	};
	updateFilelist();


	$('#encrypt').click(function(e){
		if ($("#key").val().length == 0)
		{
			alert("Please enter the encryption key.");
			return;
		}
		var files = document.getElementById("fileBrowser").files;
		if (files.length == 0)
		{
			alert("Please select files to encrypt.");
			return;
		}

		//  Encrypt each file one by one
		document.getElementById("encryptedFiles").innerHTML = "Fetching list of files...";
		for (var i = 0; i < files.length; i++)
		{
			var file = files[i];

			if (file.name.length > 255)
			{
				alert("Error: filename '" + file.name + "' is more than 255 characters long. Skipping...");
				continue;
			}

			//  First, send file metadata to enable buffer.
			var connection = new WebSocket("ws://10.0.0.100:81");
			connection.onopen = function () { connection.send(JSON.stringify({
				data: "C"+file.size.toString()+'\0'
			})); };
			connection.onmessage = function (e) {
				//  Check for status
			console.log(e);
				if (e.data == "Ready")
					connection.send(JSON.stringify({
						data: file.slice(0) + new Array(16 - file.size%16 + 1).join('0') + $("#key").val().padStart(16, 0) + 'E' + file.name + "\0"
					}));
				else if (e.data == "ENOMEM")
					alert('Error: File is larger than 250MB.');
				else
					alert('Error: unknown encryption message: ' + e.data);
			};
			connection.onerror = function (error) { alert('Error: websocket connection failed: file "' + file.name + '" ' + error); };
		}
		updateFilelist();
	});

	$('#decrypt').click(function(e){
		if ($("#key").val().length == 0)
		{
			alert("Please enter the encryption key.");
			return;
		}
		var filelist = $("#filesToDecrypt").val();
		if (filelist.length == 0)
		{
			alert("Please select files to decrypt.");
			return;
		}
		var files = filelist.split(',');

		//  Decrypt each file one by one
		for (var i = 0; i < files.length; i++)
		{
			var filename = files[i].trim().name;

			var connection = new WebSocket("ws://10.0.0.100:81");
			connection.onopen = function () { connection.send(JSON.stringify({
				data: "R" + $("#key").val().padStart(16, 0) + filename + "\0"
			})); };
			connection.onmessage = function (e) {
				//  Return a JSON object
			console.log(e);
				var message = e.data;

				//  Check for status
				if (message.substring(0,7) == "Success")
					saveAs(new Blob([message.substring(7)], {type: "image"}), filename);
				else
					alert('Error: unknown decryption message: ' + message);
			};
			connection.onerror = function (error) { alert('Error: websocket connection failed: file "' + filename + '" ' + error); };
		}
	});

	$('#delete').click(function(e){
		var filelist = $("#filesToDelete").val();
		if (filelist.length == 0)
		{
			alert("Please select files to delete.");
			return;
		}
		var files = filelist.split(',');

		//  Decrypt each file one by one
		document.getElementById("encryptedFiles").innerHTML = "Fetching list of files...";
		for (var i = 0; i < files.length; i++)
		{
			var filename = files[i].trim().name;

			var connection = new WebSocket("ws://10.0.0.100:81");
			connection.onopen = function () { connection.send(JSON.stringify({
				data: "D"+filename+"\0"
			})); };
			connection.onmessage = function (e) { alert("Delete message: " + e.data + filename); };
			connection.onerror = function (error) { alert('Error: websocket connection failed: file "' + filename + '" ' + error); };
		}

		updateFilelist();
	});
});