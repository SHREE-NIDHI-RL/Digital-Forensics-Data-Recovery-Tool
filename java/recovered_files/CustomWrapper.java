class SpeedWrapperClass{
 	private int speed;
  	SpeedWrapperClass(){ //abstraction without function
	}
	SpeedWrapperClass(int speed){
		this.speed=speed;
	}
	public int getvehicleSpeed(int speed){
		return speed;  
	}
     	public void setvehiclespeed(int speed){
            this.speed=speed;
    }	
}
public class CustomWrapper{
	public static void main(String[] args){
    	  SpeedWrapperClass speedValue=new SpeedWrapperClass(100);
	System.out.println(speedValue); //automatic class wrapping
	}
}