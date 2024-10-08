import 'package:flutter/material.dart';

class Sensorattach22 extends StatelessWidget {
  const Sensorattach22({super.key});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Colors.white,
      appBar: AppBar(
        backgroundColor: Color(0xFFFFF6F6),
        leading: IconButton(
          icon: Icon(Icons.arrow_back_ios_rounded, color: Colors.black, size: 34,),
          onPressed: () {
            Navigator.pop(context);
          },
        ),
        title: Text(
          '사용 방법',
          style: TextStyle(fontSize: 19, fontWeight: FontWeight.bold),
        ),
        centerTitle: true,
        elevation: 0,
      ),
      body: Container(
        color: Color(0xFFFFF8F9),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text("  ECG 센서 부착", style: TextStyle(fontWeight: FontWeight.bold, fontSize: 25),),
            SizedBox(height:0,),
            Padding(
              padding: const EdgeInsets.all(0.0),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.center,
                children: [
                  Image.asset('img/sensorattachment.png', width: 260,height: 260,),
                  Padding(
                    padding: const EdgeInsets.all(20.0),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(" 1. 센서를 부착할 부의의 피부가 깨끗하고 건조한지 확인해주세요",
                          style: TextStyle(fontWeight: FontWeight.bold, fontSize: 18),),
                        SizedBox(height: 5,),
                        Text(" 2. ECG센서를 정확한 위치에 부착하세요."
                          , style: TextStyle(fontWeight: FontWeight.bold, fontSize: 18),),
                        SizedBox(height: 5,),
                        Text(" 3. 검사가 진행되는 동안 과도한 움직임은 피하세요. "
                          , style: TextStyle(fontWeight: FontWeight.bold, fontSize: 18),),
                        SizedBox(height: 5,),
                        Text(" 4. 검사 중 불편감이 느껴지면 즉시 센서를 제거하고 검사를 중지하세요."
                          , style: TextStyle(fontWeight: FontWeight.bold, fontSize: 18),),
                        SizedBox(height: 7,),
                        Text(" 필요한 경우 의료 전문가에게 상담하십시오"
                          , style: TextStyle(fontWeight: FontWeight.bold, fontSize: 16),),
                        SizedBox(height: 50,),
                      ],
                    ),
                  ),
                ],
              ),
            ),
          ],

        ),
      ),
    );;
  }
}
