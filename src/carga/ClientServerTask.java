package carga;

import java.io.IOException;
import java.net.UnknownHostException;

import logica.Cliente;
import uniandes.gload.core.Task;

public class ClientServerTask extends Task{
    
	private int id = 1;
	private int fallos;
	@Override
	public void execute(){
		try {
			Cliente cliente = new Cliente(id);
			cliente.ejecutar();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		id++;
	}
	@Override
	public void fail() {
		// TODO Auto-generated method stub
		System.out.println(Task.MENSAJE_FAIL);
		fallos++;
		System.out.println(fallos);
	}
	@Override
	public void success() {
		// TODO Auto-generated method stub
		System.out.println(Task.OK_MESSAGE);
	}
	
	
}
