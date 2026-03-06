import 'package:flutter_test/flutter_test.dart';

import 'package:unixsock_example/main.dart';

void main() {
  testWidgets('renders unixsock demo controls', (WidgetTester tester) async {
    await tester.pumpWidget(const UnixsockExampleApp());

    expect(find.text('unixsock example'), findsOneWidget);
    expect(find.textContaining('Status:'), findsOneWidget);
    expect(find.text('Run Echo Test'), findsOneWidget);
  });
}
